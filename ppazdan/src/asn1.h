#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>

#define DEBUG

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

class ASN1Parser {
public:
    static std::shared_ptr<ASN1Object> decode(const std::vector<uint8_t>& data, size_t offset);
    static std::shared_ptr<ASN1Object> decode_all(const std::vector<uint8_t>& data);
    static const char* get_string_type(ASN1Tag tag);
};

class ASN1Object {
private:
    ASN1Tag tag; // ASN.1 tag
    size_t tag_length_size; // Size of tag+length fields (in bytes)
    std::vector<uint8_t> value; // Value bytes
    std::vector<std::shared_ptr<ASN1Object>> children; // Set of child objects (1 level deep); empty if there're no children
public:
    ASN1Object(ASN1Tag tag, size_t total_length, const std::vector<uint8_t>& value);
    ~ASN1Object();

    inline size_t total_length() const {
        return tag_length_size + value.size();
    }

    friend std::shared_ptr<ASN1Object> ASN1Parser::decode(const std::vector<uint8_t>&, size_t);
    friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(const std::vector<uint8_t>&);
    void print(int = 0);
};