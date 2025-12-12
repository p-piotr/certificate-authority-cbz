#include "PKCSObjects.h"
#include "sign.h"

namespace PKCS {

// 1. overloaded << operators to print contents of PKCS objects in JSONesque style
//    I also tried to add examples


// Example: AttributeTypeAndValue = { type: 1.1.1.1, value: TEST}
// I decided not to include value_type in the output as I think it would add unnecessary clutter
std::ostream& operator<<(std::ostream& os, const PKCS::AttributeTypeAndValue &ATAV){
    os  << "AttributeTypeAndValue = {type: " 
        << ATAV.type 
        << ", value: " 
        << ATAV.value 
        << "}";
    return os;
}

// Example: RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST}, AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }
std::ostream& operator<<(std::ostream& os, const RelativeDistinguishedName &RDN) {
    os << "RelativeDistinguishedName = { ";

    const auto &attrs = RDN.attributes;
    // adding each AttributeTypeAndValue to the stream
    for (size_t i = 0; i < attrs.size(); ++i) {
        os << attrs[i];
        // first method of getting rid of trailing comma
        if (i + 1 < attrs.size()) os << ", ";
    }

    os << " }";
    return os;
}

// Example: rdnSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 3.3.3.3, value: SETT}, AttributeTypeAndValue = {type: 4.4.4.4, value: TTES} } ]
std::ostream& operator<<(std::ostream& os, const rdnSequence &rdnS) {
    os << "rdnSequence = [ ";

    const auto &RDNs = rdnS.RDNSequence;
    // adding each RDN to the stream
    for (size_t i = 0; i < RDNs.size(); ++i) {
        os << RDNs[i];
        // trailing comma
        if (i + 1 < RDNs.size()) os << ", ";
    }

    os << " ]";
    return os;
}


// Example: AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00}
std::ostream& operator<<(std::ostream& os, const PKCS::AlgorithmIdentifier &AI) {
    os  << "AlgorithmIdentifier = {algorithm: "
        << AI.algorithm
        << ", parameters:";

    const auto &param = AI.parameters;

    // print parameters as hex
    // setfill('0') setw(2) to print values under 16 as 2 chars
    // I think it should be cast to it to print as integer
    os << std::hex << std::setfill('0');
    for(uint8_t byte : param){
        os << " 0x" << std::setw(2) << std::setfill ('0') << static_cast<int>(byte);
    }

    // change back from std::hex to std::dec
    os << std::dec << "}";
    return os;
}

// Example: RSAPublicKey: = {n: 1234123412341234123412341234123413241234134, e: 12384123841239412342314823041234218}
std::ostream& operator<<(std::ostream &os, const PKCS::RSAPublicKey &PK){
    os << "RSAPublicKey: = {n: " << PK.n << ", e: " << PK.e << "}";
    return os;
}

// Example: SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234, e: 1234}}
std::ostream& operator<<(std::ostream &os, const PKCS::SubjectPublicKeyInfo &SPKI){
    os << "SubjectPublicKeyInfo = { "
        << SPKI.algorithm
        << " "
        << SPKI.subjectPublicKey
        << "}";
    return os;
}

// Example: Attribute = { Type: 2.2.2.1, values = [ (tag: 22 "test"), (tag: 12 "meow"), (tag: 19 "TEST") ] }
std::ostream& operator<<(std::ostream &os, const PKCS::Attribute &ATTR){
    using variant_object = 
    variant<
    string,
    vector<uint8_t> 
    >;

    os  << "Attribute = {"
        << " Type: "
        << ATTR.type
        << ", values = [ ";

    bool first = true; 
    // used in second method of avoding danling commas
 
    // iterate thorugh the vector of pairs
    // adding each value to the stream
    for(const auto &PAIR : ATTR.values){
        // first values is is the varaiant second the tag
        const variant_object &val = PAIR.first;
        const ASN1_tag &tag = PAIR.second;

        // dangling commas avoidance
        if(!first) { os << ", "; }
        first = false;

        os << "(tag: " << tag << " ";

        // Detailed explaination of the std::visit code:
        //
        // std::visit([&tag, &val, &os](auto &&arg) { ... }, val);
        // "visit takes a variant and a set of functions, and calls the correct function based on the type the variant is holding at the time."
        // https://www.reddit.com/r/cpp_questions/comments/12ur4wv/what_exactly_are_stdvisit_and_stdvariant/
        //
        // It is usually done with lambda function as we don't want to name the function
        // in lambda:
        // [] = which values from local scope we should allow lambda to access
        // () = parameters
        // {} = body
        // val = variant - second argument to the std::visit function
        // auto&& arg = will know if arg is lvalue or rvalue and will deduce type based on that
        // https://stackoverflow.com/questions/13230480/what-is-the-meaning-of-a-variable-with-type-auto
        //
        // using T = std::decay_t<decltype(arg)>; 
        // decltype(arg) - detects type of arg at compile-time
        // std::decay_t - removes qualifiers and references such as const or &&
        // It's done because we will compare type of arg to some type like std::string
        // we want this compare to also work for const &string etc. so we just strip those
        //
        // if constexpr (std::is_same_v<T, std::string>) { ... }
        // if constexpr - we want to compare times at compile-time and constexpr will be evaluated at compile-time if used in a constant expression
        // std::is_same<T, U>::value = a class that compares type of T and U; and stores the result into value member 
        // note that std::is_same_v<T, U> can also be used
        //
        std::visit([&val, &os, &first](auto&& arg) { 
            // this is just used for convinence 
            using T = std::decay_t<decltype(arg)>; 

            // string
            if constexpr (std::is_same<T, std::string>::value) {
                os << "\"" << arg << "\"";
            } 
            // byte vector
            else if constexpr (std::is_same<T, vector<uint8_t>>::value){
                os << "bytes[ " << std::hex << std::setfill('0');
                // print each byte
                for(uint8_t byte : arg){
                    os << " 0x" << std::setw(2) << std::setfill ('0') << static_cast<int>(byte);
                }

                os << std::dec << " ]";
            }
        }, val);
        os << ")";
    }
    os << " ] }";
    return os;
}

// Example:
// CertificationRequestInfo = {Version = 0, subjectName = rdnSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.6, value: PL} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.8, value: Lesser Poland} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.10, value: AGH} } ], subjectPKInfo = SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234567890, e: 987654321}}, attributes = [Attribute = { Type: 1.2.840.113549.1.1.1, values = [ (tag: 12 "example.com") ] }] }
std::ostream& operator<<(std::ostream &os, const PKCS::CertificationRequestInfo &CRI){
    os  << "CertificationRequest = {"
        << "Version = "<< CRI.version << ", "
        << "subjectName = " << CRI.subjectName << ", "
        << "subjectPKInfo = " << CRI.subjectPKInfo << ", "
        << "attributes = [";

    // comma trailing prevention
    bool first = true;

    // print every attribute
    for(const auto &attr : CRI.attributes){
        if(!first) { os << ", "; }
        first = false;
        os << attr;
    }

    os << "] }";
    return os;
}

std::ostream& operator<<(std::ostream &os, PKCS::CertificationRequest &CR){
    os  << "CertificationRequestInfo = { " 
        << CR.certificationRequestInfo << ", "
        << CR.signatureAlgorithm << ", "
        << "Signature: "
        
    // print signature's bytes
        << std::hex << std::setfill('0');
    for(const uint8_t byte : CR.signature){
        os << std::setw(2) << static_cast<int>(byte);
    }

    os << std::dec << " }";
    return os;
}

std::ostream& operator<<(std::ostream& os, PKCS::RSAPrivateKey PK){
    os  << "RSAPrivatekey: = {n: "  
        << PK.n 
        << ", e: " 
        << PK.e 
        << ", d: " 
        << PK.d 
        << ", p: " 
        << PK.p 
        << ", q: " 
        << PK.q 
        << ", dP:" 
        << PK.dP 
        << ", dQ: " 
        << PK.dQ  
        << ", qInv : "
        << PK.qInv
        <<" }";
    return os;
}

std::ostream& operator<<(std::ostream &os, PrivateKeyInfo &PKI){ 
    os << "PrivateKeyInfo = { version = " << PKI.version << ", PrivateKeyAlgorithm: " << PKI.privateKeyAlgorithm << ", privateKey: " << PKI.privateKey;
    return os;
}


// ----------------------------------------------------------------------------------------------------
// 2. encode functions 
// Note that not all functions have been created yet



vector<uint8_t> AttributeTypeAndValue::encode() const {
    return encode_der_sequence({                // AttributeTypeAndValue is a SEQUENCE
        encode_der_oid(type),                   // type is OID
        encode_der_string(value, value_type)    // value is a string
    });
}

vector<uint8_t> RelativeDistinguishedName::encode() const {

    // RDN is a SET so we need to first create a vector of vectors that holds encoded components
    vector<vector<uint8_t>> encoded_components;
    encoded_components.reserve(attributes.size());

    // encode each attribute
    for (auto &attr : attributes){
        encoded_components.emplace_back(std::move(attr.encode()));
    }

    return encode_der_set(encoded_components);
}

vector<uint8_t> rdnSequence::encode() const {
    // rdnSequence is a SEQUENCE so we need to first create a vector of vectors that holds encoded components
    vector<vector<uint8_t>> encoded_components;

    // encode each RDN
    for (auto &RDN : RDNSequence){
        encoded_components.emplace_back(RDN.encode());
    }

    return encode_der_sequence(encoded_components);
}




vector<uint8_t> AlgorithmIdentifier::encode() const {
    return encode_der_sequence({        // AlgorithmIdentifier is a SEQUENCE
        encode_der_oid(algorithm),      // OID
        parameters                      // parameters are already stored as raw bytes as we don't use them
    });
}


vector<uint8_t> RSAPublicKey::encode() const {
    return encode_der_bitstring(    // both OCTET STRING
        encode_der_sequence({       // and a SEQUENCE
            encode_der_integer(n),  // INTEGER
            encode_der_integer(e)   // INTEGER
        })
    );
}


vector<uint8_t> SubjectPublicKeyInfo::encode() const {
    return encode_der_sequence({    //SubjectPublicKeyInfo is a SEQUENCE
        algorithm.encode(),        
        subjectPublicKey.encode()
    });
}


vector<uint8_t> Attribute::encode() const {
    // encoding based on different types
    vector<vector<uint8_t>> encoded_components;

    for(const auto &element : values){
        // variant of each element in values
        const variant_object &val = element.first;

        // tag of each element in values
        const ASN1_tag &tag = element.second;

        switch(tag){
            case PRINTABLE_STRING:
            case IA5_STRING:
            case UTF8_STRING:
                // std::get() will throw an error if it's not of this type but that means that
                // tag stores incorrect information which shouldn't have happened in the first place
                encoded_components.push_back(encode_der_string(std::get<string>(val), tag)); //             here STRING
                break;

            case OCTET_STRING:
                encoded_components.push_back(encode_der_octet_string(std::get<vector<uint8_t>>(val))); //   here OCTET STRING
                break;

            default:
                throw MyError("Attribute.encode(): Tag " + std::to_string(tag) + " isn't currently handled by the encode function");
                break;
        }
    }

    return encode_der_sequence({            // Attribute is a SEQUENCE 
        encode_der_oid(type),               // OID
        encode_der_set(encoded_components)  // value is a SET
    }); 
}


vector<uint8_t> CertificationRequestInfo::encode() const {
    vector<vector<uint8_t>> encoded_components = {
        encode_der_integer(version),    // INTEGER
        subjectName.encode(), 
        subjectPKInfo.encode() 
    };

    // For reasons that elude me these attributes are encoded with with a non-universal tag 0xA0
    // so we need to encoded them seperately to add this tag
    vector<uint8_t> encoded_attrs;
    for(const Attribute &attr : attributes){
        vector<uint8_t> temp = attr.encode();
        encoded_attrs.insert(encoded_attrs.end(), temp.begin(), temp.end());
    }
    encoded_components.push_back(encode_der_non_universal(encoded_attrs, ATTRIBUTES_CONSTRUCTED_TYPE));

    return encode_der_sequence(encoded_components);
}



vector<uint8_t> RSAPrivateKey::encode() const {
    return encode_der_sequence({        // SEQUENCE
        encode_der_integer(version),    // INTEGER
        encode_der_integer(n),          // INTEGER
        encode_der_integer(e),          // INTEGER
        encode_der_integer(d),          // INTEGER
        encode_der_integer(p),          // INTEGER
        encode_der_integer(q),          // INTEGER
        encode_der_integer(dP),         // INTEGER
        encode_der_integer(dQ),         // INTEGER
        encode_der_integer(qInv),       // INTEGER
    });
}



vector<uint8_t> CertificationRequest::encode() const {
    return encode_der_sequence({            // SEQUENCE
        certificationRequestInfo.encode(), 
        signatureAlgorithm.encode(), 
        encode_der_bitstring(signature)     // BIT STRING
    });
}


// ----------------------------------------------------------------------------------------------------
// 3. decode functions 
// Note that most of the functions have been created yet
// they use try-catch to produce nested errors


AlgorithmIdentifier AlgorithmIdentifier::decode(const vector<uint8_t> &der_buffer, size_t &offset){
    try {
        // we need this 2 values to know how many params there are
        size_t length = decode_der_sequence(der_buffer, offset);    // decode SEQUENCE tag + length
        size_t start = offset;

        string OID = decode_der_oid(der_buffer, offset);            // decode OID to use in type

        // we store parameters as pure bytes
        vector<uint8_t> params;
        params.reserve(offset - length + 1);
        while(offset < start + length){
            params.push_back(der_buffer[offset++]);
        }

        return AlgorithmIdentifier(std::move(OID), std::move(params));

    } 
    catch (const MyError &e) {
        std::throw_with_nested(MyError("AlgorithmIdentifier::decode: "));
    }
}

RSAPrivateKey RSAPrivateKey::decode(const vector<uint8_t> &der_buffer, size_t offset){
    try{
        // we discard return values they are not needed
        decode_der_octet_string(der_buffer, offset);    // decode OCTET STRING tag + length
        decode_der_sequence(der_buffer, offset);        // decode SEQUENCE tag + length

        // decode version and test if zero
        int version_ = decode_der_integer(der_buffer, offset).get_ui();     
        if(version_ != 0) { throw MyError("RSAPrivateKey::decode(): version is not zero"); }

        // decode each INTEGER one by one
        mpz_class n_ = decode_der_integer(der_buffer, offset);
        mpz_class e_ = decode_der_integer(der_buffer, offset);
        mpz_class d_ = decode_der_integer(der_buffer, offset);
        mpz_class p_ = decode_der_integer(der_buffer, offset);
        mpz_class q_ = decode_der_integer(der_buffer, offset);
        mpz_class dP_ = decode_der_integer(der_buffer, offset);
        mpz_class dQ_ = decode_der_integer(der_buffer, offset);
        mpz_class qInv_ = decode_der_integer(der_buffer, offset);

        return RSAPrivateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_));

    } catch (const MyError &e) {
        std::throw_with_nested(MyError("RSAPrivateKey::decode(): bytes didn't match expected structure"));
    }
}


PrivateKeyInfo PrivateKeyInfo::decode(const vector<uint8_t> &der_buffer, size_t &offset){
    try{
        // discards return value - not needed
        decode_der_sequence(der_buffer, offset);            // decode SEQUENCE tag + length
        
        // decode version and test if zero
        size_t version_ = decode_der_integer(der_buffer, offset).get_ui();
        if(version_ != 0) { throw MyError("RSAPrivateKey::decode(): version is not zero"); }

        AlgorithmIdentifier AI = AlgorithmIdentifier::decode(der_buffer, offset);
        RSAPrivateKey RSAPK = RSAPrivateKey::decode(der_buffer, offset);
        return PrivateKeyInfo(std::move(AI), std::move(RSAPK));

    } catch (const MyError &e) {
        std::throw_with_nested(MyError("PKCS::PrivateKeyInfo::decode: "));
    }
}



// generate signature for CSR
vector<uint8_t> CertificationRequest::sign(const PrivateKeyInfo &private_key){
    try {
        signature = RSASSA_PKCS1_V1_5_SIGN(private_key.getPrivateKeyReference(), certificationRequestInfo.encode());
        return signature;
    } catch ( const MyError &e) {
        print_nested(e);
        exit(1);
    }
}





}
