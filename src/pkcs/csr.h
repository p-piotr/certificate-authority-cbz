#pragma once

#include <cstdint>
#include <unordered_map>
#include <string>
#include "pkcs/pkcs.h"
#include "pkcs/public_key.h"

namespace CBZ::PKCS {

    namespace CSRSupportedAlgorithms{

        enum algorithm_t : uint32_t {
            sha256WithRSAEncryption = 0x5001,
            sha256
        };

        // unordered map that maps algorithm_t types to it's correspoing OID
        extern const std::unordered_map<uint32_t, std::string> algorithmMap;
    }

    // https://datatracker.ietf.org/doc/html/rfc5280#section-4.1
    //    SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //      algorithm            AlgorithmIdentifier,
    //      subjectPublicKey     BIT STRING  }
    class SubjectPublicKeyInfo{
    private:
        struct AlgorithmIdentifier _algorithm;
        RSAPublicKey _subject_public_key;
    public:
        // Example: SubjectPublicKeyInfo SPKI1;
        SubjectPublicKeyInfo() {}

        // Example: SubjectPublicKeyInfo SPKI2(AlgorithmIdentifier("1.2.840.113549.1.1.1"), RSAPublicKey("1234", "1234"));
        SubjectPublicKeyInfo(AlgorithmIdentifier algorithm, RSAPublicKey subject_public_key) : _algorithm(std::move(algorithm)), _subject_public_key(std::move(subject_public_key)) {}

        // Example: SubjectPublicKeyInfo SPKI3(rsaEncryption, mpz_class("1234"), mpz_class("1234"));
        SubjectPublicKeyInfo(CSRSupportedAlgorithms::algorithm_t algorithm, mpz_class n, mpz_class e) : _algorithm{algorithm, std::shared_ptr<void>(nullptr)}, _subject_public_key(std::move(n), std::move(e)) {}

        ASN1Object to_asn1() const;

        // encode to DER
        std::vector<uint8_t> encode() const;

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const PKCS::SubjectPublicKeyInfo& SPKI);

        // getters
        const PKCS::AlgorithmIdentifier& getAlgorithmReference() const { return _algorithm; }
        const PKCS::RSAPublicKey& getPublicKeyReference() const { return _subject_public_key; }

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
        std::string _type; 

        // technically there is no limit to what it can store so it's impossible to handle all possible nested types
        // Here maybe are all attributes:
        // https://www.itu.int/ITU-T/formal-language/itu-t/x/x520/2012/SelectedAttributeTypes.html
        

        // modify this if additional types are to be allowed in variant_object
        using variant_object = 
        std::variant<
        std::string,
        std::vector<uint8_t> 
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

        // returns encoded bytes
        // It assumes that tag stores sensible information
        std::vector<uint8_t> encode() const; 

        // << operator
        friend std::ostream& operator<<(std::ostream& os, const PKCS::Attribute& ATTR);

        // getters
        const std::string& getTypeReference() const { return _type; }
        const std::vector<std::pair<variant_object, ASN1Tag>>& getValuesReference() const { return _values; }
    };

}