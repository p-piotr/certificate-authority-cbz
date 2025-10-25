#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <gmpxx.h>

namespace ASN1 {
    class ASN1Object;
}

namespace RSA {
    bool _RSAPrivateKey_format_check(std::shared_ptr<ASN1::ASN1Object> root_object);
}

namespace ASN1 {

    // Chosen set of ASN.1 tags
    enum ASN1Tag {
        INTEGER = 0x02,
        BIT_STRING = 0x03,
        OCTET_STRING = 0x04,
        NULL_TYPE = 0x05,
        OBJECT_IDENTIFIER = 0x06,
        UTF8_STRING = 0x0C,
        SEQUENCE = 0x30,
        SET = 0x31,
        PRINTABLE_STRING = 0x13,
        IA5_STRING = 0x16,
        UTC_TIME = 0x17,
        GENERALIZED_TIME = 0x18,
    };

    // Look for definition below
    class ASN1Object;

    // Responsible for parsing ASN.1
    class ASN1Parser {
    public:
        // This function parses ASN.1 binary data and returns a parsed element (does not parse recursively - see ASN1Parser::decode_all)
        // Input:
        // @data - byte vector containing ASN.1 binary data
        // @offset - offset from the beginning of @data from which parsing should be started
        static std::shared_ptr<ASN1Object> decode(std::vector<uint8_t> const &data, size_t offset);

        // Parses ASN.1 binary data recursively to create a module tree, returning the root element
        // Input:
        // @data - byte vector containing ASN.1 binary data
        // @offset - offset in @data to start from
        static std::shared_ptr<ASN1Object> decode_all(std::vector<uint8_t> const &data, size_t offset);

        // Converts an ASN.1 tag (enum) to string
        static const char* tag_to_string(ASN1Tag tag);
    };

    // Class representing an ASN.1 object - contains a tag (see ASN1Tag above),
    // raw value and children, if parsed recursively
    class ASN1Object {
    protected:
        ASN1Tag _tag; // ASN.1 tag
        size_t _tag_length_size; // Size of tag+length fields (in bytes)
        std::vector<uint8_t> _value; // Value bytes
        std::vector<std::shared_ptr<ASN1Object>> _children; // Set of child objects (1 level deep); empty if there're no children

    public:
        ASN1Object(ASN1Tag tag, size_t total_length, std::vector<uint8_t> const &&value);
        ~ASN1Object();

        // returns object's tag
        inline ASN1Tag tag() const {
            return _tag;
        }

        // returns object's total size (in bytes) - that sums up the tag field size, length field size and the size of a value buffer
        inline size_t total_size() const {
            return _tag_length_size + _value.size();
        }

        inline const std::vector<uint8_t>& value() const {
            return _value;
        }

        inline const std::vector<std::shared_ptr<ASN1Object>>& children() const {
            return _children;
        }

        // Prints the ASN.1 tree in readable format - function prototype, most probably won't be used so I don't really care about it
        void print(int = 0);

        // friends may take what's protected stuff instead of asking for it
        // those friends need to be able to push elements inside the _children vector
        friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::vector<uint8_t> const &data, size_t offset);
        friend bool RSA::_RSAPrivateKey_format_check(std::shared_ptr<ASN1Object> root_object);
    };


    // Responsible for encoding/decoding ASN.1 OBJECT IDENTIFIER objects
    class ASN1ObjectIdentifier : public ASN1Object{
    public:
        inline const std::string value() const {
            return decode(_value);
        }

        // The ASN.1 OBJECT IDENTIFIER encoder - returns a binary representation of OBJECT IDENTIFIER (as a buffer)
        // Input:
        // @obj_id_str - OBJECT IDENTIFIER as a string (eg. "1.23.4567.89.0")
        static std::vector<uint8_t> encode(std::string const &obj_id_str);

        // ASN.1 OBJECT IDENTIFIER decoder - outputs a string (eg. "1.23.4567.89.0")
        // Input:
        // @obj_id - vector containing binary representatoin of the OBJECT IDENTIFIER
        static std::string decode(std::vector<uint8_t> const &obj_id);
    };

    // Responsible for encoding/decoding ASN.1 INTEGER objects
    class ASN1Integer : public ASN1Object {
    public:
        inline const mpz_class value() const {
            return decode(_value);
        }

        // Encodes a GMP integer to the binary form, big-endian (ANS.1 compatibile), returning a buffer
        // Input:
        // @num - GMP integer to encode
        static std::vector<uint8_t> encode(mpz_class const &num);

        // Decodes a buffer holding binary data into a GMP integer and returns it
        // Input:
        // @buffer - buffer holding the integer in binary form (big-endian)
        static mpz_class decode(std::vector<uint8_t> const &buffer);
    };

    // // ASN1ObjectIdentifier helper functions
    // std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer);
    // mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::reverse_iterator rb, std::vector<uint8_t>::reverse_iterator re);
}