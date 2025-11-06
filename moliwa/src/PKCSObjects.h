#ifndef PKCSOBJECTS_H
#define PKCSOBJECTS_H

#include "utils.h"
#include "encoding.h"
#include "decoding.h"


// This file contains the bulk of the program;
// This is where classes that represent PKCS structures reside
// Apart from the data it stores each class also contains the following:
//
// - An overloaded constructor; I tried to make it possible to construct the objects in multiple ways;
//   but it frankly turned out to be a bit cumbersome as when trying to follow this principle I ended up adding some boilerplate code;
//   also note that arguments are passed to every constructor by value; this is by design but can cause unnecessary copies;
//   to avoid the copies every object should be created with std::move e.g. AttributeTypeAndValue example(std::move(str1), std::move(str2));
//   also not sure If I haven't forgotten to use std::move or emplace_back which again can cause unnecessary copies
//   almost every constructor was prepended with a comment that gives an example of initialization to which could be sued to call it
//
// - an overload for ostream << operator that prints out the content of the object in a style that's reminiscent of JSON; It can sometimes be useful in debugging;
//
// - function encode() that returns vector<uint8_t> that contains bytes that hold the representation of this object in ASN.1/DER 
//
// - static function decode() it can be used to instantiate the object directly from DER encoded bytes
//   it takes two arguments: 
//   @der_buffer - const reference to a buffer that contains DER bytes
//   @offset - size_t that tells the function where should it start decoding
//   these functions usually just call decode_der_x in some order and they will throw an error if the bytes don't match the expected encoding
//   it was made static so it could be used instead of a constructor e.g. private_key = PKCS::PrivateKeyInfo::decode(file_buffer,offset);
//   Note: I haven't yet implemented decode() function for most classes as they weren't needed yet
//
// - getters to references to all attributes of the class;
//  
// all classes are part of the PKCS namespace
// every class was prepended with a comment that indicates which PCKS structure it represents
// to make this file a bit shorter some functions were moved to PKCSObjects.cpp

namespace PKCS{

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.indicates what kind of value is stored in this SEQUENCE
//     type     AttributeType,
//     value    AttributeValue }
//   AttributeType ::= OBJECT IDENTIFIER
//   AttributeValue ::= ANY -- DEFINED BY AttributeType
class AttributeTypeAndValue{
private:
    // OID that indicates what kind of value is stored in this SEQUENCE
    string type; 

    // the actuall value that this class stores
    // IMPORTANT: technically value has type of ANY
    // so It could be anything else other than a string
    // I'm 99% sure that we won't need this class to store anything else;
    // Making this class capable of storing different values is absolutely possible (look PKCS::Attribute class)
    // However it would make this class more complicated than it should be so I am going to leave it as it is;
    string value;

    // Needed so we know which tag should be used when encoding the object
    ASN1_tag value_type;

public:
    // Constructors: 
    
    // Example: PKCS::AttributeTypeAndValue ATAV1;
    AttributeTypeAndValue() {}

    // Example: PKCS::AttributeTypeAndValue ATAV2{"2.5.4.6", "PL"};
    AttributeTypeAndValue(string type_, string value_) {
        // if we have to construct the class using the OID and value
        // if we don't give it explicit ASN1_tag it will check the in AttributeStringType map which ASN1_tag should be used for this type
        // if OID is not found, it will assume UTF8_STRING
        // it also calls validate_string_type to check if it doesn't contain any illegal chars
        // I think this code fragment appears some time later but I haven't made an inline for it yet
        try {
            value_type = AttributeStringType.at(type_);
        } catch (const std::out_of_range &e) { 
            value_type = UTF8_STRING;
        }

        if(validate_string_type(value_, value_type) == false){
            throw MyError("AttributeTypeAndValue(string, string): attempt to create object with value that contains illegal characters");
        }
        type = std::move(type_);
        value = std::move(value_);
    }

    // Example: PKCS::AttributeTypeAndValue ATAV3{"2.5.4.6", "PL", PRINTABLE_STRING};
    // Here ASN1_tag is defined explicitly so we need check if it's a string type and then if it doesn't contain illega chars
    AttributeTypeAndValue(string type_, string value_, ASN1_tag value_type_) {
        if(value_type_ != UTF8_STRING && 
            value_type_ != IA5_STRING && 
            value_type_ != PRINTABLE_STRING){
            throw MyError("AttributeTypeAndValue(string, string, ASN1_tag): values different than strings that are currently not handled");
        }

        if(validate_string_type(value,value_type) == false){
            throw MyError("AttributeTypeAndValue(string, string, ASN1_tag): attempt to create object with value that contains illegal characters");
        }
        value_type = value_type_;
        type = std::move(type_);
        value = std::move(value_);
    }

    // returns AttributeTypeAndValue as DER encoded Bytes
    vector<uint8_t> encode() const;

    // getters to reference to private components
    const string& getTypeReference() const { return type; }
    const string& getValueReference() const { return value; }
    const ASN1_tag& getValueTypeReference() const { return value_type; }

    // overload << operator to allow to seamlessly view contents of the class
    friend std::ostream& operator<<(std::ostream& os, const PKCS::AttributeTypeAndValue &ATAV);
};



//----------------------------------------------------------------------------------------------------



// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
// RelativeDistinguishedName ::=
//     SET SIZE (1..MAX) OF AttributeTypeAndValue
//
// Note that SET is just like SEQUENCE but must be sorted when encoded it's already handled by encode_der_set
class RelativeDistinguishedName {
private:
    vector<PKCS::AttributeTypeAndValue> attributes;
public:
    // Constructors: 
    
    // Example: PKCS::RelativeDistinguishedName RDN1;
    RelativeDistinguishedName() {};

    // Example: PKCS::RelativeDistinguishedName RDN2{PKCS::AttributeTypeAndValue{"2.5.4.6", "PL"}};
    // Used to create PKCS with a single element;
    RelativeDistinguishedName(PKCS::AttributeTypeAndValue ATAV) : attributes({std::move(ATAV)}) {}

    // Exmaple: PKCS::RelativeDistinguishedName RDN3{"2.5.4.6", "PL"};
    // Used to create PKCS with a single element
    RelativeDistinguishedName(string oid, string value) : RelativeDistinguishedName(std::move(PKCS::AttributeTypeAndValue(std::move(oid),std::move(value)))) {}

    // Example: PKCS::RelativeDistinguishedName RDN4{{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}};
    RelativeDistinguishedName(std::initializer_list<PKCS::AttributeTypeAndValue> list) : attributes(list) {}

    // returns RelativeDistinguishedName as DER encoded bytes
    vector<uint8_t> encode() const;

    // getter
    const vector<PKCS::AttributeTypeAndValue>& getAttributesReference() const { return attributes; }

    // overload << operator
    friend std::ostream& operator<<(std::ostream& os, const PKCS::RelativeDistinguishedName &RDN);
};



// ----------------------------------------------------------------------------------------------------



// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
//   Name ::= CHOICE { -- only one possibility for now --
//   rdnSequence  RDNSequence }
//
//  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

// A bit of a similar situation that rdnSequence could technically store something else
// but for now there's only on possibility so I'm not going to overcomplicate this
class rdnSequence {
    vector<PKCS::RelativeDistinguishedName> RDNSequence;
public:

    // Constructors: 
    
    // Example: PKCS::rdnSequence rdnS1;
    rdnSequence() {}

    // Example: PKCS::rdnSequence rdnS2 { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} };
    // Example: PKCS::rdnSequence rdnS3 { {{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}} };
    // Note that the 2 initializations above are not equal;
    // In the first one rdnSequence contains 2 AttributeTypeAndValue each with 1 element
    // In the second one rdnSequence contains 1 AttributeTypeAndValue with 2 elements
    rdnSequence(std::initializer_list<PKCS::RelativeDistinguishedName> list) : RDNSequence(std::move(list)) {}

    // Example: vector<pair<string,string>> vec1{{"2.5.4.6","PL"}, {"2.5.4.10","AGH"}}; rdnSequence rdsn1(vec1);
    rdnSequence(vector<pair<string,string>> list) {
        for(auto& [OID, val] : list){
            RDNSequence.emplace_back(std::move(OID), std::move(val));
        }
    }

    // reference getter
    const vector<PKCS::RelativeDistinguishedName>& getRDNSequenceReference() const { return RDNSequence; }

    // overloaded << operator
    friend std::ostream& operator<<(std::ostream& os, const PKCS::rdnSequence &rdnS);

    // returns rdnSequence as DER encoded bytes
    vector<uint8_t> encode() const;
};




// ----------------------------------------------------------------------------------------------------




// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.1.2
// https://www.itu.int/rec/T-REC-X.509-198811-S
// AlgorithmIdentifier ::= SEQUENCE{
//      algorithm OBJECT IDENTIFIER
//      parameters ANY DEFINED BY algorithm OPTIONAL}
//
//  https://datatracker.ietf.org/doc/html/rfc3447#appendix-C
// As of now we are only handling this 2 algorithms
//  PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
//  { OID sha256WithRSAEncryption    PARAMETERS NULL } |
//  { OID rsaEncryption              PARAMETERS NULL }
class AlgorithmIdentifier {
private:
    // OID incdicating used algorithm
    string algorithm; 

    // This defines parameters used in the algorithm
    // they aren't even needed as the algorithm we doesn't require parameters
    vector<uint8_t> parameters;

public:
    // I believe that using different algorithm might require total refactor of this class as I don't know how other algorithms handle parameters

    //Example: AlgorithmIdentifier();
    AlgorithmIdentifier() {}

    // Example: AlgorithmIdentifier("1.2.840.113549.1.1.1")
    AlgorithmIdentifier(string algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(std::move(algorithm_)), parameters(std::move(parameters_)) {
    }

    // Example: AlgorithmIdentifier(rsaEncryption)
    AlgorithmIdentifier(algorithm_t algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm((AlgorithmsToOIDs.at(algorithm_))), parameters(std::move(parameters_)) {
    }

    // creates AlgorithmIdentifier object from DER bytes
    static AlgorithmIdentifier decode(const vector<uint8_t> &der_buffer, size_t &offset);

    // returns AlgorithmIdentifier as DER encoded Bytes
    vector<uint8_t> encode() const;

    // getters 
    const string& getAlgorithmReference() const { return algorithm; }
    const vector<uint8_t>& getParametersReference() const { return parameters; }

    // << operator
    friend std::ostream& operator<<(std::ostream& os, const PKCS::AlgorithmIdentifier &AI);

};




// ----------------------------------------------------------------------------------------------------

 

// https://www.rfc-editor.org/rfc/rfc2313.html#section-7.1
// 
// RSAPublicKey ::= SEQUENCE {
//   modulus INTEGER, -- n
//   publicExponent INTEGER -- e }
class RSAPublicKey{
private:
    mpz_class n;
    mpz_class e;
public:
    // Example: mpz_class num1("1234"); mpz_class num2("4321"); RSAPublicKey(num1, num2);
    RSAPublicKey() {}

    // Example: mpz_class num1("1234"); mpz_class num2("4321"); RSAPublicKey(num1, num2);
    RSAPublicKey(mpz_class modulus_, mpz_class exponent_) : n(std::move(modulus_)), e(std::move(exponent_)) {}

    // Example: RSAPublicKey("1234", "4321")
    RSAPublicKey(string modulus_, string exponent_) : n(std::move(modulus_)), e(std::move(exponent_)) {}

    // returns RSAPublicKey as DER encoded bytes
    vector<uint8_t> encode() const;

    // << operator
    friend std::ostream& operator<<(std::ostream &os, const PKCS::RSAPublicKey &PK);

    // getters
    const mpz_class& getNReference() const { return n; }
    const mpz_class& getEReference() const { return e; }
};


// https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
//    SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }
class SubjectPublicKeyInfo{
private:
    AlgorithmIdentifier algorithm;
    RSAPublicKey subjectPublicKey;
public:
    // Example: SubjectPublicKeyInfo SPKI1;
    SubjectPublicKeyInfo() {}

    // Example: SubjectPublicKeyInfo SPKI2(AlgorithmIdentifier("1.2.840.113549.1.1.1"), RSAPublicKey("1234", "1234"));
    SubjectPublicKeyInfo(AlgorithmIdentifier algorithm_, RSAPublicKey subjectPublicKey_) : algorithm(std::move(algorithm_)), subjectPublicKey(std::move(subjectPublicKey_)) {}

    // Example: SubjectPublicKeyInfo SPKI3("1.2.840.113549.1.1.1", "1234", "1234");
    SubjectPublicKeyInfo(string algorithm_, string n_, string e_) : algorithm(std::move(algorithm_)), subjectPublicKey(std::move(n_), std::move(e_)) {}

    // Example: SubjectPublicKeyInfo SPKI3("1.2.840.113549.1.1.1", mpz_class("1234"), mpz_class("1234"));
    SubjectPublicKeyInfo(string algorithm_, mpz_class n_, mpz_class e_) : algorithm(std::move(algorithm_)),  subjectPublicKey(std::move(n_), std::move(e_)) {}

    // Example SubjectPublicKeyInfo SPKI5(rsaEncryption, "1234", "1234");
    SubjectPublicKeyInfo(algorithm_t algorithm_, string n_, string e_) : algorithm(std::move(algorithm_)), subjectPublicKey(std::move(n_), std::move(e_)) {}

    // Example: SubjectPublicKeyInfo SPKI3("1.2.840.113549.1.1.1", mpz_class("1234"), mpz_class("1234"));
    SubjectPublicKeyInfo(algorithm_t algorithm_, mpz_class n_, mpz_class e_) : algorithm(std::move(algorithm_)),  subjectPublicKey(std::move(n_), std::move(e_)) {}

    // encode to DER
    vector<uint8_t> encode() const;

    // << operator
    friend std::ostream& operator<<(std::ostream &os, const PKCS::SubjectPublicKeyInfo &SPKI);

    // getters
    const PKCS::AlgorithmIdentifier& getAlgorithmReference() const { return algorithm; }
    const PKCS::RSAPublicKey& getPublicKeyReference() const { return subjectPublicKey; }

};



// ----------------------------------------------------------------------------------------------------



//https://www.rfc-editor.org/rfc/rfc2986.html#section-4.1
//   Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
//   Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
//        type   ATTRIBUTE.&id({IOSet}),
//        values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
//   }
class Attribute{
    // OID that indicate what type it is
    string type; 

    // technically there is no limit to what it can store so it's impossible to handle all possible nested types
    // Here maybe are all attributes:
    // https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html
    

    // modify this if additional types are to be allowed in variant_object
    using variant_object = 
    variant<
    string,
    vector<uint8_t> 
    >;

    vector<pair<variant_object,ASN1_tag>> values;             

public:
    Attribute() {}
    Attribute(
    string type_,
    vector<pair<variant_object,ASN1_tag>> values_) : type(std::move(type_)), values(std::move(values_)) {}
    
    // Single string constructor with tag
    // Example: Attribute Attr1("1.1.1.1", "test", IA5_STRING);
    Attribute(string type_, string value_,  ASN1_tag tag_) {
        if(tag_ != UTF8_STRING && tag_ != IA5_STRING && tag_ != PRINTABLE_STRING){
            throw MyError("Attribute(string, tag): Tag doesn't match string type");
        }
        if(validate_string_type(value_,tag_) == false){
            throw MyError("Attribute(string, tag): attempt to create object with value that contains illegal characters");
        }
        values.emplace_back(std::move(value_), tag_);
        type = std::move(type_);
    }


    // Single string constructor
    // Example: Attribute Attr2("2.2.2.2", "test");
    Attribute(string type_, string value_) {
        ASN1_tag tag_;
        try {
            tag_ = AttributeStringType.at(type);
            if(validate_string_type(value_, tag_) == false){
                throw MyError("Attribute(string): value_ contains illegal chars");
            }
        } catch (const std::out_of_range &e) { 
            tag_ = UTF8_STRING;
        }
        values.emplace_back(std::move(value_), tag_);
        type = std::move(type_);
    }

    // Multiple string constructor with explicit tags
    // Example Attribute Attr3("3.3.3.3", {std::make_pair("test", IA5_STRING), {"meow",UTF8_STRING}, {"TEST",PRINTABLE_STRING}});
    // Note the make pair, without it constructor call might become ambigious
    Attribute(string type_, std::initializer_list<pair<string,ASN1_tag>> list ) {
        values.reserve(list.size());
        for (auto &v : list){
            if(v.second != UTF8_STRING && v.second != IA5_STRING && v.second != PRINTABLE_STRING){
                throw MyError("Attribute({string, tag}): Tag doesn't match string type");
            }
            if(validate_string_type(v.first,v.second) == false){
                throw MyError("Attribute({string, tag}): attempt to create object with value that contains illegal characters");
            }
            values.emplace_back(std::move(v.first), v.second);
            type = std::move(type_);
        }
    }

    // Multiple string constructor
    // Exmaple Attribute Attr4("4.4.4.4", {"test", "TEST"});
    Attribute(string type_, std::initializer_list<string> list ) {
        values.reserve(list.size());
        for (auto &v : list){
            ASN1_tag tag_;
            try {
                tag_ = AttributeStringType.at(type);
                if(validate_string_type(v,tag_) == false){
                    throw MyError("Attribute(string): attempt to create object with value that contains illegal characters");
                }
            } catch (const std::out_of_range &e) { 
                tag_ = UTF8_STRING;
            }
            values.emplace_back(std::move(v), tag_);
        }
        type = std::move(type_);
    }

    // single byte array constructor
    // Example Attribute Attr5("5.5.5.5", vector<uint8_t>{1,2,3,4,5}, OCTET_STRING);
    Attribute(string type_, vector<uint8_t> value_, ASN1_tag tag) : type(std::move(type_)) {
        values.emplace_back(std::move(value_), tag);
    }

    // multiple byte array constructor
    // Example: Attribute Attr6("6.6.6.6", {{std::move(vec1),OCTET_STRING}, {std::move(vec2), OCTET_STRING}, {std::move(vec3),OCTET_STRING}});
    Attribute(string type_, vector<pair<vector<uint8_t>,ASN1_tag>> list ) : type(std::move(type_)) {
        for (auto &v : list){
            values.emplace_back(std::move(v.first), v.second);
        }
    }

    // returns encoded bytes
    // It assumes that tag stores sensible information
    vector<uint8_t> encode() const; 

    // << operator
    friend std::ostream& operator<<(std::ostream &os, const PKCS::Attribute &ATTR);

    // getters
    const string& getTypeReference() const { return type; }
    const vector<pair<variant_object,ASN1_tag>>& getValuesReference() const { return values; }
};



// ----------------------------------------------------------------------------------------------------



//https://datatracker.ietf.org/doc/html/rfc2986#page-5
//  -- Certificate requests
//  CertificationRequestInfo ::= SEQUENCE {
//      version       INTEGER { v1(0) } (v1, ... ),
//      subject       Name,
//      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
//      attributes    [0] Attributes{{ CRIAttributes }}
//  }
class CertificationRequestInfo {
private:
    // Version is always set to 0
    int version = 0;
    
    // contains information about subject that sends the request
    PKCS::rdnSequence subjectName;

    // contains information about sender's public key
    PKCS::SubjectPublicKeyInfo subjectPKInfo;

    // contains additional data fields
    vector<PKCS::Attribute> attributes;

public:
    // Example: CertificationRequestInfo CRI1
    CertificationRequestInfo() {}

    // Example:
    //     CertificationRequestInfo CRI2(rdnSequence({{"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"}}), 
    //                            SubjectPublicKeyInfo(rsaEncryption, "1234567890", "987654321"),
    //                            {Attribute("1.2.840.113549.1.1.1", "example.com")});
    CertificationRequestInfo(PKCS::rdnSequence subjectName_, PKCS::SubjectPublicKeyInfo subjectPKInfo_, vector<PKCS::Attribute> attributes_) :
    subjectName(std::move(subjectName_)), subjectPKInfo(std::move(subjectPKInfo_)), attributes(std::move(attributes_)) {}


    // Example:
    //CertificationRequestInfo CRI3( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
    //                              rsaEncryption, std::move(mpz_class("1234567890")), std::move(mpz_class("987654321")),
    //                              { {"1.2.840.113549.1.1.1", "example.com"} });
    CertificationRequestInfo(vector<pair<string,string>> subjectName_, algorithm_t algorithm_, mpz_class n_, mpz_class e_, vector<pair<string,string>> attributes_) 
    : subjectName(std::move(subjectName_)), subjectPKInfo(std::move(algorithm_), std::move(n_), std::move(e_)){
        for(auto& [OID, val] : attributes_){
            attributes.emplace_back(std::move(OID), std::move(val));
        }
    }

    // Same as above but use string with OID instead of rsaEncryption
    CertificationRequestInfo(vector<pair<string,string>> subjectName_, string algorithm_, mpz_class n_, mpz_class e_, vector<pair<string,string>> attributes_) 
    : subjectName(std::move(subjectName_)), subjectPKInfo(std::move(algorithm_), std::move(n_), std::move(e_)){
        for(auto& [OID, val] : attributes_){
            attributes.emplace_back(std::move(OID), std::move(val));
        }
    }

    // Example:
    //CertificationRequestInfo CRI4( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
    //                              rsaEncryption, "1234567890", "987654321",
    //                              { {"1.2.840.113549.1.1.1", "example.com"} });
    CertificationRequestInfo(vector<pair<string,string>> subjectName_, algorithm_t algorithm_, string n_, string e_, vector<pair<string,string>> attributes_) 
    : subjectName(std::move(subjectName_)), subjectPKInfo(std::move(algorithm_), std::move(n_), std::move(e_)){
        for(auto& [OID, val] : attributes_){
            attributes.emplace_back(std::move(OID), std::move(val));
        }
    }

    // Same as above but use string with OID instead of rsaEncryption
    CertificationRequestInfo(vector<pair<string,string>> subjectName_, string algorithm_, string n_, string e_, vector<pair<string,string>> attributes_) 
    : subjectName(std::move(subjectName_)), subjectPKInfo(std::move(algorithm_), std::move(n_), std::move(e_)){
        for(auto& [OID, val] : attributes_){
            attributes.emplace_back(std::move(OID), std::move(val));
        }
    }

    vector<uint8_t> encode() const;

    // << operator
    friend std::ostream& operator<<(std::ostream &os, const PKCS::CertificationRequestInfo &CRI);

    // getters
    const PKCS::rdnSequence& getSubjectNameReference() const { return subjectName; }
    const PKCS::SubjectPublicKeyInfo& getsubjectPKinfoReference() const { return subjectPKInfo; }
    const vector<PKCS::Attribute>& getAttributesReference() const { return attributes; }

    // does not include signature

};



// ----------------------------------------------------------------------------------------------------



// https://www.rfc-editor.org/rfc/rfc2313.html#section-7.2
//    An RSA private key shall have ASN.1 type RSAPrivateKey:
// RSAPrivateKey ::= SEQUENCE {
//   version Version,
//   modulus INTEGER, -- n
//   publicExponent INTEGER, -- e
//   privateExponent INTEGER, -- d
//   prime1 INTEGER, -- p
//   prime2 INTEGER, -- q
//   exponent1 INTEGER, -- d mod (p-1)
//   exponent2 INTEGER, -- d mod (q-1)
//   coefficient INTEGER -- (inverse of q) mod p }
// Version ::= INTEGER
class RSAPrivateKey {
private:
    //always zero
    int version;

    mpz_class n, e, d, p, q, dP, dQ, qInv;
public:
    RSAPrivateKey() {}

    //Example: RSAPrivateKey RPK(mpz_class("1"), mpz_class("2"), mpz_class("3"), mpz_class("4"), mpz_class("5"), mpz_class("6"), mpz_class("7"), mpz_class("8"));
    RSAPrivateKey (
    mpz_class n_,
    mpz_class e_,
    mpz_class d_,
    mpz_class p_,
    mpz_class q_,
    mpz_class dP_,
    mpz_class dQ_,
    mpz_class qInv_
    ) : version(0), n(std::move(n_)), e(std::move(e_)), d(std::move(d_)), p(std::move(p_)), q(std::move(q_)), dP(std::move(dP_)), dQ(std::move(dQ_)), qInv(std::move(qInv_)) {}

    //Example: RSAPrivateKey RPK("1", "2", "3", "4", "5", "6", "7", "8");
    RSAPrivateKey (
    string n_,
    string e_,
    string d_,
    string p_,
    string q_,
    string dP_,
    string dQ_,
    string qInv_
    ) : version(0), n(std::move(n_)), e(std::move(e_)), d(std::move(d_)), p(std::move(p_)), q(std::move(q_)), dP(std::move(dP_)), dQ(std::move(dQ_)), qInv(std::move(qInv_)) {}


    // creates this object using DER bytes
    static RSAPrivateKey decode(const vector<uint8_t> &der_buffer, size_t offset);

    // returns object as DER encoded bytes
    vector<uint8_t> encode() const;

    // getters
    const mpz_class& getNReference() const { return n; }
    const mpz_class& getEReference() const { return e; }
    const mpz_class& getDReference() const { return d; }
    const mpz_class& getPReference() const { return p; }
    const mpz_class& getQReference() const { return q; }
    const mpz_class& getDPReference() const { return dP; }
    const mpz_class& getDQReference() const { return dQ; }
    const mpz_class& getQInvReference() const { return qInv; }

    // << operator
    friend std::ostream& operator<<(std::ostream& os, PKCS::RSAPrivateKey PK);
};




// ----------------------------------------------------------------------------------------------------




// PrivateKeyInfo ::= SEQUENCE {
//        version                   Version,
//        privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//        privateKey                PrivateKey,
//        attributes           [0]  IMPLICIT Attributes OPTIONAL }
//      Version ::= INTEGER
//      PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//      PrivateKey ::= OCTET STRING
//      Attributes ::= SET OF Attribute
//
// Attribute are OPTIONAL so I decided to skip them as I noticed that most tools I tried do skip them
class PrivateKeyInfo {
    int version;
    AlgorithmIdentifier privateKeyAlgorithm;
    RSAPrivateKey privateKey;
public:
    PrivateKeyInfo(const AlgorithmIdentifier &privateKeyAlgorithm_, const RSAPrivateKey &privateKey_, int version_ = 0) : version(version_), privateKeyAlgorithm(std::move(privateKeyAlgorithm_)), privateKey(std::move(privateKey_)) {}

    // Constructors
    // I made 4 version as I assumed that you can used string or algorithm_t to indicate which algorithm was used
    // and that you can initialize mpz_class both as mpz_class and a string

    PrivateKeyInfo() {}
    //Example: PrivateKeyInfo RPK(rsaEncryption "1", "2", "3", "4", "5", "6", "7", "8");
    PrivateKeyInfo (
    algorithm_t algorithm_,
    mpz_class n_,
    mpz_class e_,
    mpz_class d_,
    mpz_class p_,
    mpz_class q_,
    mpz_class dP_,
    mpz_class dQ_,
    mpz_class qInv_,
    int version_ = 0
    ) : privateKeyAlgorithm(algorithm_), privateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_)),  version(version_) {}

    PrivateKeyInfo (
    string algorithm_, mpz_class n_, mpz_class e_, mpz_class d_, mpz_class p_, mpz_class q_, mpz_class dP_, mpz_class dQ_, mpz_class qInv_, int version_ = 0
    ) : privateKeyAlgorithm(algorithm_), privateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_)),  version(version_) {}

    PrivateKeyInfo (
    string algorithm_, string n_, string e_, string d_, string p_, string q_, string dP_, string dQ_, string qInv_, int version_ = 0
    ) : privateKeyAlgorithm(algorithm_), privateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_)),  version(version_) {}

    PrivateKeyInfo (
    algorithm_t algorithm_, string n_, string e_, string d_, string p_, string q_, string dP_, string dQ_, string qInv_, int version_ = 0
    ) : privateKeyAlgorithm(algorithm_), privateKey(std::move(n_), std::move(e_), std::move(d_), std::move(p_), std::move(q_), std::move(dP_), std::move(dQ_), std::move(qInv_)),  version(version_) {}

    // getters
    const RSAPrivateKey& getPrivateKeyReference() const { return  privateKey; };
    const AlgorithmIdentifier& getPrivateKeyAlgorithmReference() const { return  privateKeyAlgorithm; };

    // << operator
    friend std::ostream& operator<<(std::ostream &os, PrivateKeyInfo &PKI);

    // create object from DER bytes
    static PrivateKeyInfo decode(const vector<uint8_t> &der_buffer, size_t &offset);

    };


// https://datatracker.ietf.org/doc/html/rfc2986#page-7
// 
//  CertificationRequest ::= SEQUENCE {
//       certificationRequestInfo CertificationRequestInfo,
//       signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
//       signature          BIT STRING
//  }
class CertificationRequest{
private:
    CertificationRequestInfo certificationRequestInfo;
    AlgorithmIdentifier signatureAlgorithm;
    vector<uint8_t> signature;
public:
    // Constructors
    // as above for versions for algorithm_t/string and mpz_class/string

    // Example: CertificationRequest CR1
    CertificationRequest() {}
    CertificationRequest(CertificationRequestInfo certificationRequestInfo_, AlgorithmIdentifier signatureAlgorithm_) :
    certificationRequestInfo(std::move(certificationRequestInfo_)), signatureAlgorithm(std::move(signatureAlgorithm_)) {}

    // Example:
    //CertificationRequest   CR2( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
    //                              rsaEncryption, std::move(mpz_class("1234567890")), std::move(mpz_class("987654321")),
    //                              { {"1.2.840.113549.1.1.1", "example.com"} },
    //                              sha256WithRSAEncryption
    //                              );
    CertificationRequest(vector<pair<string,string>> subjectName_, algorithm_t algorithm_, mpz_class n_, mpz_class e_, vector<pair<string,string>> attributes_, algorithm_t sig_algorithm_) 
    : certificationRequestInfo(std::move(subjectName_), algorithm_, std::move(n_), std::move(e_), std::move(attributes_)), signatureAlgorithm(sig_algorithm_) {}

    CertificationRequest(vector<pair<string,string>> subjectName_, algorithm_t algorithm_, string n_, string e_, vector<pair<string,string>> attributes_, algorithm_t sig_algorithm_) 
    : certificationRequestInfo(std::move(subjectName_), algorithm_, std::move(n_), std::move(e_), std::move(attributes_)), signatureAlgorithm(sig_algorithm_) {}


    CertificationRequest(vector<pair<string,string>> subjectName_, string algorithm_, mpz_class n_, mpz_class e_, vector<pair<string,string>> attributes_, string sig_algorithm_) 
    : certificationRequestInfo(std::move(subjectName_), std::move(algorithm_), std::move(n_), std::move(e_), std::move(attributes_)), signatureAlgorithm(std::move(sig_algorithm_)) {}

    CertificationRequest(vector<pair<string,string>> subjectName_, string algorithm_, string n_, string e_, vector<pair<string,string>> attributes_, string sig_algorithm_) 
    : certificationRequestInfo(std::move(subjectName_), std::move(algorithm_), std::move(n_), std::move(e_), std::move(attributes_)), signatureAlgorithm(std::move(sig_algorithm_)) {}

    // << operator
    friend std::ostream& operator<<(std::ostream& os, CertificationRequest &CR);

    // << getters
    const CertificationRequestInfo& getCertificationRequestInfoReference() const { return certificationRequestInfo; };
    const AlgorithmIdentifier& getSignatureAlgorithmReference() const { return signatureAlgorithm; }
    const vector<uint8_t>& getSignatureReference() const { return signature;}
    const RSAPublicKey& getPublicKeyReference() const { return certificationRequestInfo.getsubjectPKinfoReference().getPublicKeyReference(); }

    // returns content of this object as DER encoded bytes
    vector<uint8_t> encode() const;

    // function that generates a signature for Certification Request
    // signature is both stored into signature parameter of the object
    // add returned by the function
    // @private_key - key with which CSR will be signed
    // return value : signature bytes
    vector<uint8_t> sign(const PrivateKeyInfo &private_key);
};



};



#endif
