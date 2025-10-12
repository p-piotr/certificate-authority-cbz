#include <iostream>
#include <utility>
#include <string>
#include <map>
#include <sstream>
#include <cinttypes>
#include <vector>
#include <gmpxx.h>

using std::string;
using std::pair;
using std::vector;
using std::cout;
using std::endl;
using std::map;

enum string_t{
    IA5STRING,
    PRINTABLE_STRING,
    UTF8_STRING
};

static const vector<uint8_t> der_null = {0x05, 0x00};

static const map<string, vector<uint32_t>> AttributesToOIDs = {
    {"countryName",              {2, 5, 4, 6}},
    {"stateOrProvinceName",      {2, 5, 4, 8}},
    {"localityName",             {2, 5, 4, 7}},
    {"organizationName",         {2, 5, 4, 10}},
    {"organizationalUnitName",   {2, 5, 4, 11}},
    {"commonName",               {2, 5, 4, 3}},
    {"emailAddress",             {1, 2, 840, 113549, 1, 9, 1}},
    {"unstructuredName",          {1, 2, 840, 113549, 1, 9, 2}},
    {"challengePassword",        {1, 2, 840, 113549, 1, 9, 7}},
    {"rsaEncryption",            {1, 2, 840, 113549, 1, 1, 1}},
    {"sha256WithRSAEncryption",  {1, 2, 840, 113549, 1, 1, 11}},
};


static const map<string, string> OIDsToAttributes = {
    {"2.5.4.6",                "countryName"},
    {"2.5.4.8",                "stateOrProvinceName"},
    {"2.5.4.7",                "localityName"},
    {"2.5.4.10",               "organizationName"},
    {"2.5.4.11",               "organizationalUnitName"},
    {"2.5.4.3",                "commonName"},
    {"1.2.840.113549.1.9.1",   "emailAddress"},
    {"1.2.840.113549.1.9.2",   "unstructuredName"},
    {"1.2.840.113549.1.9.7",   "challengePassword"}, 
    {"1.2.840.113549.1.1.1",   "rsaEncryption"}, 
    {"1.2.840.113549.1.1.11",  "sha256WithRSAEncryption"},
};

static const map<string, string_t> AttributeStringTypes = {
    {"2.5.4.6",                PRINTABLE_STRING},   // countryName
    {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
    {"2.5.4.7",                UTF8_STRING},        // localityName
    {"2.5.4.10",               UTF8_STRING},        // organizationName
    {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
    {"2.5.4.3",                UTF8_STRING},        // commonName
    {"1.2.840.113549.1.9.1",   IA5STRING},          // emailAddress
    {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
    {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
};


vector<uint8_t> encode_der_length(size_t length){
    vector<uint8_t> out;
    if (length < 0x80) {
        out.push_back(static_cast<uint8_t>(length));
        return out;
    }
    else {
        vector<uint8_t> len_bytes;
        size_t temp = length;
        while (temp > 0){
            len_bytes.insert(len_bytes.begin(), static_cast<uint8_t>((temp & 0xFF)));
            temp >>= 8;
        }

        uint8_t prefix = (0x80 | static_cast<uint8_t>(len_bytes.size()));
        out.push_back(prefix);
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
    }
    return out;
}

vector<uint8_t> encode_der_integer(const mpz_class &value) {
    vector<uint8_t> bytes;

    if(value == 0){
        return {0x02, 0x01, 0x00};
    }

    bool negative = (value < 0);
    mpz_class abs_value = negative ? -value : value;

    while(abs_value > 0) {
        mpz_class mpzbyte = (abs_value & 0xFF);
        uint8_t byte = mpzbyte.get_ui();
        bytes.insert(bytes.begin(), byte);
        abs_value >>= 8;
    }

    if(negative){
        // two's complement
        for(auto &b : bytes)
            b = ~b;
        for(int i = bytes.size() - 1; i >= 0; i--){
            if(++bytes[i] != 0) break;
        }

        if((bytes[0] & 0x80) == 0)
            bytes.insert(bytes.begin(), 0xFF);
    }
    else{
        while(bytes.size() > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0)
            bytes.erase(bytes.begin());
        if(bytes[0] & 0x80)
            bytes.insert(bytes.begin(), 0x00);
    }

    
    vector<uint8_t> der = {0x02};
    vector<uint8_t> length = encode_der_length(bytes.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), bytes.begin(), bytes.end());

    return der;
}

static vector<uint8_t> encode_oid_component(uint32_t value) {
    vector<uint8_t> encoding;
    do{
        encoding.insert(encoding.begin(), static_cast<uint8_t>((value & 0x7F)));
        value >>= 7;
    } while (value > 0);

    for (size_t i = 0; i < encoding.size() - 1; i++)
        encoding[i] |= 0x80;

    return encoding;
}

vector<uint8_t> encode_der_oid(const vector<uint32_t>& oid){
    if (oid.size() < 2){
        throw std::invalid_argument("OID must have at least two components");
    }

    vector<uint8_t> oid_enc;
    oid_enc.push_back(static_cast<uint8_t>(oid[0] * 40 + oid[1]));
    for (size_t i = 2; i < oid.size(); i++){
        vector<uint8_t> enc = encode_oid_component(oid[i]);
        oid_enc.insert(oid_enc.end(), enc.begin(), enc.end());
    }

    vector<uint8_t> der = {0x06};
    vector<uint8_t> length = encode_der_length(oid_enc.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), oid_enc.begin(), oid_enc.end());

    return der;
}


vector<uint8_t> encode_der_string(const string &str, string_t str_type){
    vector<uint8_t> bytes(str.begin(), str.end());
    uint8_t tag;
    switch(str_type){
        case IA5STRING:
            tag = 0x16;
            break;
        case PRINTABLE_STRING:
            tag = 0x13;
            break;
        case UTF8_STRING:
            tag = 0x0C;
            break;
    }
    vector<uint8_t> der = {tag};
    vector<uint8_t> length = encode_der_length(bytes.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), bytes.begin(), bytes.end());
    return der;
}

vector<uint32_t> split_oid(const string &oid){
    //https://gist.github.com/mattearly/d8afe122912eb8872bc0fddb62a32376
    vector<uint32_t> elements;
    std::stringstream ss;
    ss.str(oid);
    string item;
    uint32_t element;
    while(std::getline(ss, item, '.')){
        element = static_cast<uint32_t>(std::stoi(item));
        elements.push_back(element);
    }
    return elements;
}

string serialize_oid(const vector<uint32_t> &oid){
    string serial = "";
    for(auto val : oid)
        serial += std::to_string(val) + '.';
    serial.pop_back();
    return serial;
}


vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>> &elements){
    vector<uint8_t> content;
    for (auto& el : elements){
        content.insert(content.end(), el.begin(), el.end());
    }
    vector<uint8_t> der = {0x30};
    vector<uint8_t> length = encode_der_length(content.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), content.begin(), content.end());
    return der;
}

class AttribiuteTypeAndValue{
    vector<uint32_t> type;   // OID;
    string value;             // Note: Specification doesn't require it to be a string;
    string_t value_type;


public:
    AttribiuteTypeAndValue(string type_, string value_, string_t value_type_=UTF8_STRING) : type(split_oid(type_)), value(value_), value_type(value_type_) {}
    AttribiuteTypeAndValue(vector<uint32_t> type_, string value_, string_t value_type_=UTF8_STRING) : type(type_), value(value_), value_type(value_type_) {}

    vector<uint8_t> encode() const {
        return encode_der_sequence({
            encode_der_oid(type),
            encode_der_string(value, value_type)
        });
    }

};

vector<uint8_t> encode_der_set(const vector<vector<uint8_t>> &elements){
    vector<vector<uint8_t>> sorted = elements;
    std::sort(sorted.begin(), sorted.end());

    vector<uint8_t> content;
    for(const auto &el : sorted)
        content.insert(content.end(), el.begin(), el.end());

    vector<uint8_t> der = {0x31};
    vector<uint8_t> length = encode_der_length(content.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), content.begin(), content.end());
    return der;
}


class RelativeDistinguishedName {
    vector<AttribiuteTypeAndValue> attrs;
public:
    RelativeDistinguishedName() = default;
    RelativeDistinguishedName(std::initializer_list<AttribiuteTypeAndValue> init) : attrs(init) {}

    vector<uint8_t> encode() const {
        vector<vector<uint8_t>> encoded;
        for (const auto &a : attrs)
            encoded.push_back(a.encode());
        return encode_der_set(encoded);
    }
};

//Note: technically Name is defined as ASN.1 CHOICE which would more accurately
//Note: correspond to Union (or Variant) but as it currently only holds only one value
//Note: I will just model it as a normal class
class rdnSequence {
    vector<RelativeDistinguishedName> sequence;
public:
    rdnSequence() = default;
    rdnSequence(std::initializer_list<RelativeDistinguishedName> init) : sequence(init) {}
    rdnSequence(vector<RelativeDistinguishedName> init) : sequence(init) {}

    vector<uint8_t> encode() const {
        vector<vector<uint8_t>> encoded;
        for (auto &rdn : sequence)
            encoded.push_back(rdn.encode());
        return encode_der_sequence(encoded);
    }
};

//  According to RFC
//  PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
//  { OID rsaEncryption              PARAMETERS NULL } |
//  { OID md2WithRSAEncryption       PARAMETERS NULL } |
//  { OID md5WithRSAEncryption       PARAMETERS NULL } |
//  { OID sha1WithRSAEncryption      PARAMETERS NULL } |
//  { OID sha256WithRSAEncryption    PARAMETERS NULL } |
//  { OID sha384WithRSAEncryption    PARAMETERS NULL } |
//  { OID sha512WithRSAEncryption    PARAMETERS NULL } |
//  { OID id-RSAES-OAEP PARAMETERS RSAES-OAEP-params } |
//  PKCS1PSourceAlgorithms                             |
//  { OID id-RSASSA-PSS PARAMETERS RSASSA-PSS-params } ,
//  ...  -- Allows for future expansion --
// }
//
//  Note: as of now only rsaEncryption is handled

class AlgorithmIdentifier {
    vector<uint32_t> algorithm; // OID
    vector<uint8_t> parameters;
    string attr;
    void constr(){
        string serial = serialize_oid(algorithm);
        try{
            attr = OIDsToAttributes.at(serial);
        } catch (const std::out_of_range& e){
            std::cerr << "Error: not handled algorithm of with OID \'" << serial << "\'" << endl;
        }

        if(attr == "1.2.840.113549.1.1.1" || attr == "1.2.840.113549.1.1.11")
            parameters = der_null;

        // If different algorithms to be handled parse parameters here
    }
public:
    AlgorithmIdentifier(string algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(split_oid(algorithm_)), parameters(parameters_) {
        constr();
    }

    AlgorithmIdentifier(vector<uint32_t> algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(algorithm_), parameters(parameters_)   {
        constr();
    }
    vector<uint8_t> encode() const {
        return encode_der_sequence({
            encode_der_oid(algorithm),
            parameters
        });
    }

};

vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bytes) {
    vector<uint8_t> out = {0x03};

    vector<uint8_t> content = {0x00}; // 0 unused bits
    content.insert(content.end(), bytes.begin(), bytes.end());

    vector<uint8_t> len = encode_der_length(content.size());
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

class PublicKey{
    mpz_class modulus;
    mpz_class exponent;
public:
    PublicKey(const mpz_class &modulus_, const mpz_class &exponent_) : modulus(modulus_), exponent(exponent_) {}
    vector<uint8_t> encode() const {
        vector<uint8_t> sequence = encode_der_sequence({encode_der_integer(modulus), encode_der_integer(exponent)});
        return encode_der_bitstring(sequence);
    }
};

class subjectPKInfo{
    AlgorithmIdentifier algorithm;
    PublicKey subjectPublicKey;
public:
    subjectPKInfo(AlgorithmIdentifier algorithm_, PublicKey subjectPublicKey_) : algorithm(algorithm_), subjectPublicKey(subjectPublicKey_) {}
    vector<uint8_t> encode() const {
        return encode_der_sequence({
            algorithm.encode(),
            subjectPublicKey.encode()
        });
    }
};

class Attribute{
    vector<uint32_t> type;   // OID;
    vector<pair<string,string_t>> values;             
public:
    Attribute(string type_, vector<pair<string,string_t>> values_) : type(split_oid(type_)), values(values_) {}
    Attribute(vector<uint32_t> type_, vector<pair<string,string_t>> values_) : type(type_), values(values_) {}

    vector<uint8_t> encode() const {
        vector<vector<uint8_t>> encoded;
        for (const auto &a : values)
            encoded.push_back(encode_der_string(a.first, a.second));

        return encode_der_sequence({
            encode_der_oid(type),
            encode_der_set(encoded)
        });
    }
};

class certificationRequestInfo {
    int version; // only 0 is valid currently
    rdnSequence Name;
    subjectPKInfo SubjectPublicKeyInfo;
    vector<Attribute> Attributes;;

public:
    certificationRequestInfo(rdnSequence Name_, subjectPKInfo SubjectPublicKeyInfo_, vector<Attribute> Attributes_, int Version_ = 0) : 
    version(Version_), 
    Name(Name_), 
    SubjectPublicKeyInfo(SubjectPublicKeyInfo_), 
    Attributes(Attributes_) {}

    certificationRequestInfo(
    const vector<pair<string,string>> & subject,
    const mpz_class &modulus,
    const mpz_class &exponent,
    const vector<pair<string,string>> &attrs = {}
    ) : 
        SubjectPublicKeyInfo({ 
        {"1.2.840.113549.1.1.1"}, // Must be RSA, only this is handled
        {modulus, exponent} 
    }) , version(0) 
    {
        vector<RelativeDistinguishedName> rdns;
        for (const auto &[key, value] : subject) {
            try{
                rdns.push_back({
                    {key, value, AttributeStringTypes.at(key)}
                });
            }  catch (const std::out_of_range& e){
                std::cerr << "Error: no match Attribiute with OID \'" << key << "\'" << endl;
            }
        }
        Name = rdnSequence(rdns);

        for (const auto &[key, value] : attrs) {
            try{
                Attributes.push_back({
                    key,
                    {
                        {value, AttributeStringTypes.at(key)}
                    }
                });
            } catch (const std::out_of_range& e){
                std::cerr << "Error: no match Attribiute with OID \'" << key << "\'" << endl;
            }
        }
    }

    vector<uint8_t> encode() const {
        vector<vector<uint8_t>> encoded = {encode_der_integer(version), Name.encode(), SubjectPublicKeyInfo.encode()};
        vector<uint8_t> content;
        for(Attribute attr : Attributes){
            vector<uint8_t> temp = attr.encode();
            content.insert(content.end(), temp.begin(), temp.end());
        }
        vector<uint8_t> der = {0x0A};
        vector<uint8_t> length = encode_der_length(content.size());
        der.insert(der.end(), length.begin(), length.end());
        der.insert(der.end(), content.begin(), content.end());
        encoded.push_back(der);

        return encode_der_sequence(encoded);
    }

};


// certificationRequestInfo CRI(
//     {
//         {"2.5.4.6", "ab"},
//         {"2.5.4.8", "cd"},
//         {"2.5.4.7", "ef"},
//         {"2.5.4.10", "gh"},
//         {"2.5.4.11", "ij"},
//         {"2.5.4.3", "kl"},
//         {"1.2.840.113549.1.9.1", "mn"}
//     },
//     mpz_class("29998119994325102740934263870958013612140431814369037011463274912294059725915571999656579689082023654213454599673104446299062998775654454664818234796765420706376318015050252611896155237284971055040520527836920955461385264904790561238796431677247296299293004972148559604927896465074978359662927084484054599897199780041432691778165333858202269177089052159546732091702726744098369502320116687031926157743163421445599275161041978215959837477409290452574595233521500081960750425613056457609724334979216999495957704779253573973290886660836435368236834936136544810438777458651258009796903224945302721241666216986167931835859"),
//     mpz_class("65537"),
//     {
//         {"1.2.840.113549.1.9.2", "1235"},
//         {"1.2.840.113549.1.9.7", "12345"}
//     }
// );



int main(){
    certificationRequestInfo CRI(
        {
            {"2.5.4.6", "AU"},
            {"2.5.4.8", "Meow"},
            {"2.5.4.10", "OwO"}
        },
        mpz_class("29998119994325102740934263870958013612140431814369037011463274912294059725915571999656579689082023654213454599673104446299062998775654454664818234796765420706376318015050252611896155237284971055040520527836920955461385264904790561238796431677247296299293004972148559604927896465074978359662927084484054599897199780041432691778165333858202269177089052159546732091702726744098369502320116687031926157743163421445599275161041978215959837477409290452574595233521500081960750425613056457609724334979216999495957704779253573973290886660836435368236834936136544810438777458651258009796903224945302721241666216986167931835859"),
        mpz_class("65537"),
        {
            {"1.2.840.113549.1.9.2", "UwU"},
            {"1.2.840.113549.1.9.7", "Test"}
        }
    );


    vector<uint8_t> bytes = CRI.encode();
    for(auto byte : bytes)
        printf("%.2X ", byte);
    cout << endl;
 
    return 0;
}
