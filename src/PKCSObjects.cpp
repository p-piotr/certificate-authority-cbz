#include "PKCSObjects.h"
#include "sign.h"
#include "pkcs/private_key.h"
#include "utils/utils.hpp"

namespace CBZ::PKCS {

// 1. overloaded << operators to print contents of PKCS objects in JSONesque style
//    I also tried to add examples


// Example: AttributeTypeAndValue = { type: 1.1.1.1, value: TEST}
// I decided not to include value_type in the output as I think it would add unnecessary clutter
std::ostream& operator<<(std::ostream& os, const PKCS::AttributeTypeAndValue& ATAV){
    os  << "AttributeTypeAndValue = {type: " 
        << ATAV._type 
        << ", value: " 
        << ATAV._value 
        << "}";
    return os;
}

// Example: RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST}, AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }
std::ostream& operator<<(std::ostream& os, const RelativeDistinguishedName& RDN) {
    os << "RelativeDistinguishedName = { ";

    const auto& attrs = RDN._attributes;
    // adding each AttributeTypeAndValue to the stream
    for (size_t i = 0; i < attrs.size(); ++i) {
        os << attrs[i];
        // first method of getting rid of trailing comma
        if (i + 1 < attrs.size()) os << ", ";
    }

    os << " }";
    return os;
}

// Example: RDNSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 3.3.3.3, value: SETT}, AttributeTypeAndValue = {type: 4.4.4.4, value: TTES} } ]
std::ostream& operator<<(std::ostream& os, const RDNSequence& rdnS) {
    os << "RDNSequence = [ ";

    const auto& RDNs = rdnS._rdn_sequence;
    // adding each RDN to the stream
    for (size_t i = 0; i < RDNs.size(); ++i) {
        os << RDNs[i];
        // trailing comma
        if (i + 1 < RDNs.size()) os << ", ";
    }

    os << " ]";
    return os;
}


// Example: SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234, e: 1234}}
std::ostream& operator<<(std::ostream& os, const PKCS::SubjectPublicKeyInfo& SPKI){
    os << "SubjectPublicKeyInfo = { "
        << SPKI.algorithm
        << " "
        << SPKI.subjectPublicKey
        << "}";
    return os;
}

// Example:
// CertificationRequestInfo = {Version = 0, subjectName = RDNSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.6, value: PL} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.8, value: Lesser Poland} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.10, value: AGH} } ], subjectPKInfo = SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234567890, e: 987654321}}, attributes = [Attribute = { Type: 1.2.840.113549.1.1.1, values = [ (tag: 12 "example.com") ] }] }
std::ostream& operator<<(std::ostream& os, const PKCS::CertificationRequestInfo& CRI){
    os  << "CertificationRequest = {"
        << "Version = "<< CRI.version << ", "
        << "subjectName = " << CRI.subjectName << ", "
        << "subjectPKInfo = " << CRI.subjectPKInfo << ", "
        << "attributes = [";

    // comma trailing prevention
    bool first = true;

    // print every attribute
    for(const auto& attr : CRI.attributes){
        if(!first) { os << ", "; }
        first = false;
        os << attr;
    }

    os << "] }";
    return os;
}

std::ostream& operator<<(std::ostream& os, PKCS::CertificationRequest& CR){
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

// std::ostream& operator<<(std::ostream& os, PKCS::RSAPrivateKey PK){
//     os  << "RSAPrivatekey: = {n: "  
//         << PK.n 
//         << ", e: " 
//         << PK.e 
//         << ", d: " 
//         << PK.d 
//         << ", p: " 
//         << PK.p 
//         << ", q: " 
//         << PK.q 
//         << ", dP:" 
//         << PK.dP 
//         << ", dQ: " 
//         << PK.dQ  
//         << ", qInv : "
//         << PK.qInv
//         <<" }";
//     return os;
// }

// std::ostream& operator<<(std::ostream& os, PrivateKeyInfo& PKI){ 
//     os << "PrivateKeyInfo = { version = " << PKI.version << ", PrivateKeyAlgorithm: " << PKI.privateKeyAlgorithm << ", privateKey: " << PKI.privateKey;
//     return os;
// }


// ----------------------------------------------------------------------------------------------------
// 2. encode functions 
// Note that not all functions have been created yet



vector<uint8_t> AttributeTypeAndValue::encode() const {
    return encode_der_sequence({                // AttributeTypeAndValue is a SEQUENCE
        encode_der_oid(_type),                   // type is OID
        encode_der_string(_value, _value_type)    // value is a string
    });
}

vector<uint8_t> RelativeDistinguishedName::encode() const {

    // RDN is a SET so we need to first create a vector of vectors that holds encoded components
    vector<vector<uint8_t>> encoded_components;
    encoded_components.reserve(_attributes.size());

    // encode each attribute
    for (auto& attr : _attributes){
        encoded_components.emplace_back(std::move(attr.encode()));
    }

    return encode_der_set(encoded_components);
}

vector<uint8_t> RDNSequence::encode() const {
    // RDNSequence is a SEQUENCE so we need to first create a vector of vectors that holds encoded components
    vector<vector<uint8_t>> encoded_components;

    // encode each RDN
    for (auto& RDN : _rdn_sequence){
        encoded_components.emplace_back(RDN.encode());
    }

    return encode_der_sequence(encoded_components);
}


vector<uint8_t> RSAPublicKey::encode() const {
    return encode_der_bitstring(    // both OCTET STRING
        encode_der_sequence({       // and a SEQUENCE
            encode_der_integer(n),  // INTEGER
            encode_der_integer(e)   // INTEGER
        })
    );
}


std::shared_ptr<std::vector<uint8_t>> SubjectPublicKeyInfo::encode() const {
    return encode_der_sequence({    //SubjectPublicKeyInfo is a SEQUENCE
        algorithm.encode(),        
        subjectPublicKey.encode()
    });
}


vector<uint8_t> Attribute::encode() const {
    // encoding based on different types
    vector<vector<uint8_t>> encoded_components;

    for(const auto& element : values){
        // variant of each element in values
        const variant_object& val = element.first;

        // tag of each element in values
        const ASN1_tag& tag = element.second;

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
    for(const Attribute& attr : attributes){
        vector<uint8_t> temp = attr.encode();
        encoded_attrs.insert(encoded_attrs.end(), temp.begin(), temp.end());
    }
    encoded_components.push_back(encode_der_non_universal(encoded_attrs, ATTRIBUTES_CONSTRUCTED_TYPE));

    return encode_der_sequence(encoded_components);
}



// vector<uint8_t> RSAPrivateKey::encode() const {
//     return encode_der_sequence({        // SEQUENCE
//         encode_der_integer(version),    // INTEGER
//         encode_der_integer(n),          // INTEGER
//         encode_der_integer(e),          // INTEGER
//         encode_der_integer(d),          // INTEGER
//         encode_der_integer(p),          // INTEGER
//         encode_der_integer(q),          // INTEGER
//         encode_der_integer(dP),         // INTEGER
//         encode_der_integer(dQ),         // INTEGER
//         encode_der_integer(qInv),       // INTEGER
//     });
// }



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


AlgorithmIdentifier AlgorithmIdentifier::decode(const vector<uint8_t>& der_buffer, size_t& offset){
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
    catch (const std::runtime_error& e) {
        std::throw_with_nested(std::runtime_error("AlgorithmIdentifier::decode: "));
    }
}

// RSAPrivateKey RSAPrivateKey::decode(const vector<uint8_t>& der_buffer, size_t offset){
//     try{
//         // we discard return values they are not needed
//         decode_der_octet_string(der_buffer, offset);    // decode OCTET STRING tag + length
//         decode_der_sequence(der_buffer, offset);        // decode SEQUENCE tag + length

//         // decode version and test if zero
//         int version_ = decode_der_integer(der_buffer, offset).get_ui();     
//         if(version_ != 0) { throw MyError("RSAPrivateKey::decode(): version is not zero"); }

//         // decode each INTEGER one by one
//         mpz_class n_ = decode_der_integer(der_buffer, offset);
//         mpz_class e_ = decode_der_integer(der_buffer, offset);
//         mpz_class d_ = decode_der_integer(der_buffer, offset);
//         mpz_class p_ = decode_der_integer(der_buffer, offset);
//         mpz_class q_ = decode_der_integer(der_buffer, offset);
//         mpz_class dP_ = decode_der_integer(der_buffer, offset);
//         mpz_class dQ_ = decode_der_integer(der_buffer, offset);
//         mpz_class qInv_ = decode_der_integer(der_buffer, offset);

//         return RSAPrivateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_));

//     } catch (const MyError& e) {
//         std::throw_with_nested(MyError("RSAPrivateKey::decode(): bytes didn't match expected structure"));
//     }
// }


// PrivateKeyInfo PrivateKeyInfo::decode(const vector<uint8_t>& der_buffer, size_t& offset){
//     try{
//         // discards return value - not needed
//         decode_der_sequence(der_buffer, offset);            // decode SEQUENCE tag + length
        
//         // decode version and test if zero
//         size_t version_ = decode_der_integer(der_buffer, offset).get_ui();
//         if(version_ != 0) { throw MyError("RSAPrivateKey::decode(): version is not zero"); }

//         AlgorithmIdentifier AI = AlgorithmIdentifier::decode(der_buffer, offset);
//         RSAPrivateKey RSAPK = RSAPrivateKey::decode(der_buffer, offset);
//         return PrivateKeyInfo(std::move(AI), std::move(RSAPK));

//     } catch (const MyError& e) {
//         std::throw_with_nested(MyError("PKCS::PrivateKeyInfo::decode: "));
//     }
// }



// generate signature for CSR
std::vector<uint8_t> CertificationRequest::sign(const RSAPrivateKey& private_key){
    try {
        signature = RSASSA_PKCS1_V1_5_SIGN(private_key, certificationRequestInfo.encode());
        return signature;
    } catch (std::runtime_error const& e) {
        CBZ::Utils::print_nested(e);
        exit(1);
    }
}
}
