#ifndef csrclass
#define csrclass

#include "mappings.h"
#include "reusable.h"
#include "encoding.h"
#include "reusable.h"
#include "openssl.h"

#include <utility>

using std::pair;
using std::endl;

// This is a series of classes nested within one another
// Most of them only have a constructor (possibly overloaded) and an encode() function
// I'm not sure if this is the correct design choice, but why not
// Example of how to construct the entire object:
// Only RSA is handled so yup
// CertificationRequest CR(
//     {
//         {"2.5.4.6", "NV"},
//         {"2.5.4.8", "Pixie Peak"},
//         {"2.5.4.7", "Critchville"},
//         {"2.5.4.10", "Dust Distrubing and Delivery"},
//         {"2.5.4.11", "MT departemnt"},
//         {"2.5.4.3", "idk"},
//         {"1.2.840.113549.1.9.1", "dddpix@pmail.nvl"}
//     },
//     mpz_class("29998119994325102740934263870958013612140431814369037011463274912294059725915571999656579689082023654213454599673104446299062998775654454664818234796765420706376318015050252611896155237284971055040520527836920955461385264904790561238796431677247296299293004972148559604927896465074978359662927084484054599897199780041432691778165333858202269177089052159546732091702726744098369502320116687031926157743163421445599275161041978215959837477409290452574595233521500081960750425613056457609724334979216999495957704779253573973290886660836435368236834936136544810438777458651258009796903224945302721241666216986167931835859"),
//     mpz_class("65537"),
//     {
//         {"1.2.840.113549.1.9.2", "Just a name"},
//         {"1.2.840.113549.1.9.7", "secret"}
//     }
// );
//

class CertificationRequest{

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

    //Note: technically rdnSequence is defined as ASN.1 CHOICE which would more accurately
    //Note: correspond to Union (or Variant) but as it currently only holds only one value
    //Note: That is Sequence of RDN; I will just model it as a normal class;
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

        //This is pretty much the main constructor that should be used
        //It's far from perfect as it always constructs object that will
        //Encode RSA + SHA256, but we probably won't do anything else so it should do
        certificationRequestInfo(
        const vector<pair<string,string>> & subject,
        const mpz_class &modulus,
        const mpz_class &exponent,
        const vector<pair<string,string>> &attrs = {}
        ) : 
            SubjectPublicKeyInfo({ 
            {"1.2.840.113549.1.1.1"}, // Must be RSA, only this is handled, class must be updated to hold other algorithms
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
            vector<uint8_t> der = {0xA0};
            vector<uint8_t> length = encode_der_length(content.size());
            der.insert(der.end(), length.begin(), length.end());
            der.insert(der.end(), content.begin(), content.end());
            encoded.push_back(der);

            return encode_der_sequence(encoded);
        }

    };


    certificationRequestInfo CRI;
    AlgorithmIdentifier signatureAlgorithm;
    vector<uint8_t> signature;
public:
    CertificationRequest(certificationRequestInfo CRI_, AlgorithmIdentifier signatureAlgorithm_) : CRI(CRI_), signatureAlgorithm(signatureAlgorithm_) {}
    CertificationRequest(
    const vector<pair<string,string>> & subject,
    const mpz_class &modulus,
    const mpz_class &exponent,
    const vector<pair<string,string>> &attrs = {})
    : CRI(subject, modulus, exponent, attrs), signatureAlgorithm("1.2.840.113549.1.1.11")     {}
    // same case as with CRI, if you want other signing algorithms this constructor will require changes;

    vector<uint8_t> encode(const string &path){
        vector<uint8_t> CRI_enc = CRI.encode();
        return encode_der_sequence({CRI_enc, signatureAlgorithm.encode(), encode_der_bitstring(rsa_sha256_sign(CRI_enc, path))});
    }
};

#endif
