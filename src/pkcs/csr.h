#pragma once

#include <cstdint>
#include <unordered_map>
#include <string>
#include "pkcs/pkcs.h"
#include "pkcs/public_key.h"

namespace CBZ::PKCS {

    namespace CSRSupportedAlgorithms {

        enum algorithm_t : uint32_t {
            rsaEncryption = 0x5001,
            sha256WithRSAEncryption,
            sha256
        };

        // unordered map that maps algorithm_t types to it's correspoing OID
        extern const std::unordered_map<uint32_t, std::string> algorithmMap;
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
    //    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //      algorithm            AlgorithmIdentifier,
    //      subjectPublicKey     BIT STRING  }
    class SubjectPublicKeyInfo {
    private:
        struct AlgorithmIdentifier _algorithm;
        RSAPublicKey _subject_public_key;
    public:
        // Example: SubjectPublicKeyInfo SPKI1;
        SubjectPublicKeyInfo() {}

        // Example: SubjectPublicKeyInfo SPKI2(AlgorithmIdentifier("1.2.840.113549.1.1.1"), RSAPublicKey("1234", "1234"));
        SubjectPublicKeyInfo(
            AlgorithmIdentifier algorithm,
            RSAPublicKey subject_public_key
        ) : 
        _algorithm(std::move(algorithm)),
        _subject_public_key(std::move(subject_public_key)) {}

        // Example: SubjectPublicKeyInfo SPKI3(rsaEncryption, mpz_class("1234"), mpz_class("1234"));
        SubjectPublicKeyInfo(
            CSRSupportedAlgorithms::algorithm_t algorithm,
            mpz_class n,
            mpz_class e
        ) :
        _algorithm{algorithm, std::shared_ptr<void>(nullptr)},
        _subject_public_key(std::move(n), std::move(e)) {}

        SubjectPublicKeyInfo(
            CSRSupportedAlgorithms::algorithm_t algorithm,
            std::string n,
            std::string e
        ) :
        _algorithm{algorithm, std::shared_ptr<void>(nullptr)},
        _subject_public_key(std::move(n), std::move(e)) {}

        ASN1Object to_asn1() const;

        // encode to DER
        std::vector<uint8_t> encode() const;

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const PKCS::SubjectPublicKeyInfo& SPKI);

        // getters
        inline const PKCS::AlgorithmIdentifier& getAlgorithmReference() const { return _algorithm; }
        inline const PKCS::RSAPublicKey& getPublicKeyReference() const { return _subject_public_key; }

    };

    // ----------------------------------------------------------------------------------------------------

    //https://www.rfc-editor.org/rfc/rfc2986.html#section-4.1
    //   Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
    //   Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
    //        type   ATTRIBUTE.&id({IOSet}),
    //        values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
    //   }
    class Attribute {
        // OID that indicate what type it is
        std::string _type; 

        // technically there is no limit to what it can store so it's impossible to handle all possible nested types
        // Here maybe are all attributes:
        // https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html
        

        // modify this if additional types are to be allowed in variant_object
        using variant_object =
            std::variant<
                std::string, std::vector<uint8_t>
            >;

        std::vector<std::pair<variant_object, ASN1Tag>> _values;

    public:
        Attribute() {}

        Attribute(std::string type, std::vector<std::pair<variant_object, ASN1Tag>> values) : _type(std::move(type)), _values(std::move(values)) {}
        
        // Single string constructor with tag
        // Example: Attribute Attr1("1.1.1.1", "test", IA5_STRING);
        Attribute(std::string type, std::string value,  ASN1Tag tag);


        // Single string constructor
        // Example: Attribute Attr2("2.2.2.2", "test");
        Attribute(std::string type, std::string value);

        // Multiple string constructor with explicit tags
        // Example Attribute Attr3("3.3.3.3", {std::make_pair("test", IA5_STRING), {"meow",UTF8_STRING}, {"TEST",PRINTABLE_STRING}});
        // Note the make pair, without it constructor call might become ambigious
        Attribute(std::string type, std::initializer_list<std::pair<std::string, ASN1Tag>> list);

        // Multiple string constructor
        // Exmaple Attribute Attr4("4.4.4.4", {"test", "TEST"});
        Attribute(std::string type, std::initializer_list<std::string> list);

        // single byte array constructor
        // Example Attribute Attr5("5.5.5.5", vector<uint8_t>{1,2,3,4,5}, OCTET_STRING);
        Attribute(std::string type, std::vector<uint8_t> value, ASN1Tag tag);

        // multiple byte array constructor
        // Example: Attribute Attr6("6.6.6.6", {{std::move(vec1),OCTET_STRING}, {std::move(vec2), OCTET_STRING}, {std::move(vec3),OCTET_STRING}});
        Attribute(
            std::string type,
            std::vector<std::pair<std::vector<uint8_t>, ASN1Tag>> list
        );

        ASN1Object to_asn1() const;
        // returns encoded bytes
        // It assumes that tag stores sensible information
        std::vector<uint8_t> encode() const; 

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const PKCS::Attribute& ATTR);

        // getters
        inline const std::string& getTypeReference() const { return _type; }
        inline const std::vector<std::pair<variant_object, ASN1Tag>>& getValuesReference() const { return _values; }
    };

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.indicates what kind of value is stored in this SEQUENCE
    //     type     AttributeType,
    //     value    AttributeValue }
    //   AttributeType ::= OBJECT IDENTIFIER
    //   AttributeValue ::= ANY -- DEFINED BY AttributeType
    class AttributeTypeAndValue {
    private:
        // OID that indicates what kind of value is stored in this SEQUENCE
        std::string _type; 

        // the actuall value that this class stores
        // IMPORTANT: technically value has type of ANY
        // so It could be anything else other than a string
        // I'm 99% sure that we won't need this class to store anything else;
        // Making this class capable of storing different values is absolutely possible (look PKCS::Attribute class)
        // However it would make this class more complicated than it should be so I am going to leave it as it is;
        std::string _value;

        // Needed so we know which tag should be used when encoding the object
        ASN1Tag _value_type;

    public:
        // Example: PKCS::AttributeTypeAndValue ATAV1;
        AttributeTypeAndValue() {}

        // Example: PKCS::AttributeTypeAndValue ATAV2{"2.5.4.6", "PL"};
        AttributeTypeAndValue(std::string type, std::string value);

        // Example: PKCS::AttributeTypeAndValue ATAV3{"2.5.4.6", "PL", PRINTABLE_STRING};
        // Here ASN1_tag is defined explicitly so we need check if it's a string type and then if it doesn't contain illega chars
        AttributeTypeAndValue(std::string type, std::string value, ASN1Tag value_type);

        ASN1Object to_asn1() const;

        // returns AttributeTypeAndValue as DER encoded Bytes
        std::vector<uint8_t> encode() const;

        // getters to reference to private components
        inline const std::string& getTypeReference() const { return _type; }
        inline const std::string& getValueReference() const { return _value; }
        inline const ASN1Tag& getValueTypeReference() const { return _value_type; }

        // overload << operator to allow to seamlessly view contents of the class
        friend std::ostream& operator<<(std::ostream& os, const AttributeTypeAndValue& atav);
    };

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
    // RelativeDistinguishedName ::=
    //     SET SIZE (1..MAX) OF AttributeTypeAndValue
    //
    // Note that SET is just like SEQUENCE but must be sorted when encoded it's already handled by encode_der_set
    class RelativeDistinguishedName {
    private:
        std::vector<AttributeTypeAndValue> _atavs;
    public:
        // Example: PKCS::RelativeDistinguishedName RDN1;
        RelativeDistinguishedName() {};

        // Example: PKCS::RelativeDistinguishedName RDN2{PKCS::AttributeTypeAndValue{"2.5.4.6", "PL"}};
        // Used to create PKCS with a single element;
        RelativeDistinguishedName(AttributeTypeAndValue atav)
            : _atavs({std::move(atav)}) {}

        // Exmaple: PKCS::RelativeDistinguishedName RDN3{"2.5.4.6", "PL"};
        // Used to create PKCS with a single element
        RelativeDistinguishedName(std::string oid, std::string value)
            : RelativeDistinguishedName((AttributeTypeAndValue(std::move(oid), std::move(value)))) {}

        // Example: PKCS::RelativeDistinguishedName RDN4{{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}};
        RelativeDistinguishedName(std::initializer_list<AttributeTypeAndValue> list)
            : _atavs(list) {}

        ASN1Object to_asn1() const;

        // returns RelativeDistinguishedName as DER encoded bytes
        std::vector<uint8_t> encode() const;

        // getter
        inline const std::vector<AttributeTypeAndValue>& getAttributesReference() const { return _atavs; }

        // overload << operator
        friend std::ostream& operator<<(std::ostream& os, RelativeDistinguishedName const& RDN);
    };

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4
    //   Name ::= CHOICE { -- only one possibility for now --
    //   RDNSequence  RDNSequence }
    //
    //  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    // A bit of a similar situation that RDNSequence could technically store something else
    // but for now there's only on possibility so I'm not going to overcomplicate this
    class RDNSequence {
        std::vector<RelativeDistinguishedName> _rdn_sequence;
    public:

        // Constructors: 
        
        // Example: PKCS::RDNSequence rdnS1;
        RDNSequence() {}

        // Example: PKCS::RDNSequence rdnS2 { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} };
        // Example: PKCS::RDNSequence rdnS3 { {{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}} };
        // Note that the 2 initializations above are not equal;
        // In the first one RDNSequence contains 2 AttributeTypeAndValue each with 1 element
        // In the second one RDNSequence contains 1 AttributeTypeAndValue with 2 elements
        RDNSequence(std::initializer_list<RelativeDistinguishedName> list)
            : _rdn_sequence(std::move(list)) {}

        // Example: vector<pair<string,string>> vec1{{"2.5.4.6","PL"}, {"2.5.4.10","AGH"}}; RDNSequence rdsn1(vec1);
        RDNSequence(std::vector<std::pair<std::string, std::string>> list);

        // reference getter
        inline const std::vector<PKCS::RelativeDistinguishedName>& getRDNSequenceReference() const { return _rdn_sequence; }

        ASN1Object to_asn1() const;

        // returns RDNSequence as DER encoded bytes
        std::vector<uint8_t> encode() const;

        // overloaded << operator
        friend std::ostream& operator<<(std::ostream& os, PKCS::RDNSequence const& rdnS);
    };

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
        int _version = 0;
        
        // contains information about subject that sends the request
        RDNSequence _subject_name;

        // contains information about sender's public key
        SubjectPublicKeyInfo _subject_pkinfo;

        // contains additional data fields
        std::vector<Attribute> _attributes;

    public:
        // Example: CertificationRequestInfo CRI1
        CertificationRequestInfo() {}

        // Example:
        //     CertificationRequestInfo CRI2(RDNSequence({{"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"}}), 
        //                            SubjectPublicKeyInfo(rsaEncryption, "1234567890", "987654321"),
        //                            {Attribute("1.2.840.113549.1.1.1", "example.com")});
        CertificationRequestInfo(
            RDNSequence subject_name,
            SubjectPublicKeyInfo subject_pkinfo, 
            std::vector<Attribute> attributes
        ) :
        _subject_name(std::move(subject_name)),
        _subject_pkinfo(std::move(subject_pkinfo)),
        _attributes(std::move(attributes)) {}



        // Example:
        //CertificationRequestInfo CRI3( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
        //                              rsaEncryption, std::move(mpz_class("1234567890")), std::move(mpz_class("987654321")),
        //                              { {"1.2.840.113549.1.1.1", "example.com"} });
        CertificationRequestInfo(
            std::vector<std::pair<std::string, std::string>> subject_name,
            CSRSupportedAlgorithms::algorithm_t algorithm,
            mpz_class n,
            mpz_class e,
            std::vector<std::pair<std::string, std::string>> attributes
        ); 

        CertificationRequestInfo(
            std::vector<std::pair<std::string, std::string>> subject_name,
            CSRSupportedAlgorithms::algorithm_t algorithm,
            std::string n,
            std::string e,
            std::vector<std::pair<std::string, std::string>> attributes
        ) :
        CertificationRequestInfo(
            std::move(subject_name),
            algorithm,
            mpz_class(std::move(n)),
            mpz_class(std::move(e)),
            std::move(attributes)
        ) {}

        // Same as above but use string with OID instead of algorithm_t
        // CertificationRequestInfo::CertificationRequestInfo(
        //     std::vector<std::pair<std::string, std::string>> subject_name,
        //     std::string algorithm,
        //     mpz_class n,
        //     mpz_class e,
        //     std::vector<std::pair<std::string, std::string>> attributes
        // );

        ASN1Object to_asn1() const;

        std::vector<uint8_t> encode() const;

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const CertificationRequestInfo& cri);

        // getters
        inline const PKCS::RDNSequence& getSubjectNameReference() const { return _subject_name; }
        inline const PKCS::SubjectPublicKeyInfo& getsubjectPKinfoReference() const { return _subject_pkinfo; }
        inline const std::vector<Attribute>& getAttributesReference() const { return _attributes; }

        // does not include signature
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
        CertificationRequestInfo _certification_request_info;
        AlgorithmIdentifier _signature_algorithm;
        std::vector<uint8_t> _signature;
    public:
        // Constructors
        // as above for versions for algorithm_t/string and mpz_class/string

        // Example: CertificationRequest CR1
        CertificationRequest() {}
        CertificationRequest(
            CertificationRequestInfo certification_request_info,
            AlgorithmIdentifier signature_algorithm
        ) :
        _certification_request_info(std::move(certification_request_info)),
        _signature_algorithm(std::move(signature_algorithm)) {}

        // Example:
        //CertificationRequest   CR2( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
        //                              rsaEncryption, std::move(mpz_class("1234567890")), std::move(mpz_class("987654321")),
        //                              { {"1.2.840.113549.1.1.1", "example.com"} },
        //                              sha256WithRSAEncryption
        //                              );
        CertificationRequest(
            std::vector<std::pair<std::string, std::string>> subject_name,
            CSRSupportedAlgorithms::algorithm_t algorithm,
            mpz_class n,
            mpz_class e,
            std::vector<std::pair<std::string, std::string>> attributes,
            CSRSupportedAlgorithms::algorithm_t sig_algorithm
        ) :
        _certification_request_info(std::move(subject_name), algorithm, std::move(n), std::move(e), std::move(attributes)),
        _signature_algorithm(sig_algorithm) {}

        CertificationRequest(
            std::vector<std::pair<std::string, std::string>> subject_name,
            CSRSupportedAlgorithms::algorithm_t algorithm,
            std::string n,
            std::string e,
            std::vector<std::pair<std::string, std::string>> attributes,
            CSRSupportedAlgorithms::algorithm_t sig_algorithm
        ) :
        CertificationRequest(
            std::move(subject_name),
            algorithm,
            mpz_class(std::move(n)),
            mpz_class(std::move(e)),
            std::move(attributes),
            sig_algorithm
        ) {}

        // CertificationRequest(
        //     std::vector<std::pair<std::string, std::string>> subject_name,
        //     std::string algorithm,
        //     mpz_class n,
        //     mpz_class e,
        //     std::vector<std::pair<std::string, std::string>> attributes,
        //     std::string sig_algorithm) :
        //     _certification_request_info(std::move(subject_name), std::move(algorithm), std::move(n), std::move(e), std::move(attributes)),
        //     _signature_algorithm(std::move(sig_algorithm)) {}

        // << getters
        inline const CertificationRequestInfo& getCertificationRequestInfoReference() const { return _certification_request_info; };
        inline const AlgorithmIdentifier& getSignatureAlgorithmReference() const { return _signature_algorithm; }
        inline const std::vector<uint8_t>& getSignatureReference() const { return _signature; }
        inline const RSAPublicKey& getPublicKeyReference() const { return _certification_request_info.getsubjectPKinfoReference().getPublicKeyReference(); }

        ASN1Object to_asn1() const;

        // returns content of this object as DER encoded bytes
        std::vector<uint8_t> encode() const;

        // function that generates a signature for Certification Request
        // signature is both stored into signature parameter of the object
        // add returned by the function
        // @private_key - key with which CSR will be signed
        // return value : signature bytes
        std::vector<uint8_t> sign(RSAPrivateKey const& private_key);

        // << operator
        friend std::ostream& operator<<(std::ostream& os, CertificationRequest& CR);
    };

}