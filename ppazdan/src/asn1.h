#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <gmpxx.h>

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

    class ASN1Object;

    // Responsible for parsing ASN.1
    class ASN1Parser {
    public:
        static std::shared_ptr<ASN1Object> decode(std::vector<uint8_t> const &data, size_t offset);
        static std::shared_ptr<ASN1Object> decode_all(std::vector<uint8_t> const &data);
        static const char* tag_to_string(ASN1Tag tag);
    };

    // Class representing an ASN.1 object - contains a tag (see ASN1Tag above),
    // raw value and children, if parsed recursively
    class ASN1Object {
    private:
        ASN1Tag tag; // ASN.1 tag
        size_t tag_length_size; // Size of tag+length fields (in bytes)
        std::vector<uint8_t> value; // Value bytes
        std::vector<std::shared_ptr<ASN1Object>> children; // Set of child objects (1 level deep); empty if there're no children
    public:
        ASN1Object(ASN1Tag tag, size_t total_length, std::vector<uint8_t> const &value);
        ~ASN1Object();

        inline size_t total_length() const {
            return tag_length_size + value.size();
        }

        friend std::shared_ptr<ASN1Object> ASN1Parser::decode(std::vector<uint8_t> const &data, size_t offset);
        friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::vector<uint8_t> const &data);
        void print(int = 0);
    };


    // Responsible for parsing ASN.1 OBJECT IDENTIFIER fields
    class ASN1ObjectIdentifier {
    public:
        static std::vector<uint8_t> encode(std::string const &obj_id_str);
        static std::string decode(std::vector<uint8_t> const &obj_id);
    };

    // ASN1ObjectIdentifier helper functions
    std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer);
    mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::reverse_iterator rb, std::vector<uint8_t>::reverse_iterator re);
}