#include "PKCSObjects.h"
#include "sign.h"

//overloaded << operators to print contents of PKCS objects in JSONesque style
namespace PKCS {
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
    for (size_t i = 0; i < attrs.size(); ++i) {
        os << attrs[i];
        if (i + 1 < attrs.size()) os << ", ";
    }
    os << " }";
    return os;
}

// Example: rdnSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 3.3.3.3, value: SETT}, AttributeTypeAndValue = {type: 4.4.4.4, value: TTES} } ]
std::ostream& operator<<(std::ostream& os, const rdnSequence &rdnS) {
    os << "rdnSequence = [ ";
    const auto &RDNs = rdnS.RDNSequence;
    for (size_t i = 0; i < RDNs.size(); ++i) {
        os << RDNs[i];
        if (i + 1 < RDNs.size()) os << ", ";
    }
    os << " ]";
    return os;
}


// Example AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00}
std::ostream& operator<<(std::ostream& os, const PKCS::AlgorithmIdentifier &AI) {
    os  << "AlgorithmIdentifier = {algorithm: "
        << AI.algorithm
        << ", parameters:";
    const auto &param = AI.parameters;
    os << std::hex << std::setfill('0');
    for(uint8_t byte : param){
        os << " 0x" << std::setw(2) << std::setfill ('0') << static_cast<int>(byte);
    }
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
    bool first = true; // used to avoid danling commas after last element
    // iterate thorugh the vector of pairs
    for(const auto &PAIR : ATTR.values){
        // first values ist he variant
        const variant_object &val = PAIR.first;
        const ASN1_tag &tag = PAIR.second;

        if(!first) { os << ", "; }
        first = false;
        os << "(tag: " << tag << " ";

        // Detailed explaination of the std::visit code:
        //
        // std::visit([&tag, &val, &os](auto &&arg) { ... }, val);
        // I don't really know exactly why but when you want work with variants you have to use visit
        // "visit takes a variant and a set of functions, and calls the correct function based on the type the variant is holding at the time."
        // https://www.reddit.com/r/cpp_questions/comments/12ur4wv/what_exactly_are_stdvisit_and_stdvariant/
        // It is usually done with lambda function as we don't want to name the function
        // in lambda:
        // [] = which values from local scope we should allow lambda to access
        // () = parameters
        // {} = body
        // val = variant - second argument to the std::visit function
        // auto&& arg = will (somehow) know if arg is lvalue or rvalue and will deduce type based on that
        // auto&& - honestly I don't understand why we use in std::visit lambda but all examples I seen do that
        // (I think this is just good practice and we want to capture all possible options)
        // https://stackoverflow.com/questions/13230480/what-is-the-meaning-of-a-variable-with-type-auto
        //
        // using T = std::decay_t<decltype(arg)>; 
        // decltype(arg) - detects type of arg at compile-time
        // std::decay_t - removes qualifiers and references such as const or &&
        // It's done because we will compare type of arg to some static type like std::string in a second 
        // we want this compare to also work for const &string etc. so we just strip those
        //
        // if constexpr (std::is_same_v<T, std::string>) { ... }
        // if constexpr = compare at compile-time 
        // std::is_same<T, U>::value = Is a class that compares type of T and U; and stores the result into value member 
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
    bool first = true;
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

vector<uint8_t> CertificationRequest::sign(const PrivateKeyInfo &private_key){
    vector<uint8_t> encoded_certificate_request_info = certificationRequestInfo.encode();
    signature = RSASSA_PKCS1_V1_5_SIGN(private_key.getPrivateKeyReference(), encoded_certificate_request_info);
    return signature;
}

}
