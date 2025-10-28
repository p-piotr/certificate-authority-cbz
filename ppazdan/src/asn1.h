#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <gmpxx.h>
#include "debug.h"
#include "security.h"

// Question: why is ASN1 namespace declared 2 times + RSA namespace declaration in the middle of ASN1?
// Answer: https://en.wikipedia.org/wiki/Circular_dependency

// This namespace is defined in fully defined later on - forward declaration of ASN1Object for the function down below in the RSA namespace
namespace ASN1 {
    class ASN1Object;
}

// This namespace is defined in "rsa.h" - forward declaration of a function used as a friend in ASN1Object
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
        // This function parses ASN.1 binary data and returns a parsed element 
        // (does not parse recursively - see ASN1Parser::decode_all)
        //
        // Input:
        // @data - byte vector containing ASN.1 binary data
        // @offset - offset from the beginning of @data from which parsing should be started
        static std::shared_ptr<ASN1Object> decode(std::shared_ptr<std::vector<uint8_t>> data, size_t offset);

        // Parses ASN.1 binary data recursively to create a module tree, returning the root element
        //
        // Input:
        // @data - shared pointer to byte vector containing ASN.1 binary data 
        // as an rvalue - this buffer will be managed by ASN1ObjectData instances 
        // and safely destroyed when no longer needed (memory zeroed before deallocation)
        // @offset - offset in @data to start from
        static std::shared_ptr<ASN1Object> decode_all(std::vector<uint8_t> &&data, size_t offset);

        // Parses ASN.1 binary data recursively to create a module tree, returning the root element
        // This function operates on an already created shared pointer to a byte vector
        //
        // Input:
        // @data - shared pointer to byte vector containing ASN.1 binary data
        // @offset - offset in @data to start from
        static std::shared_ptr<ASN1Object> decode_all(std::shared_ptr<std::vector<uint8_t>> data, size_t offset);

        // Converts an ASN.1 tag (enum) to string
        static const char* tag_to_string(ASN1Tag tag);
    };

    // This class wraps the overall binary structure of an ASN.1 object tree
    // Before, all ASN1Object instances contained their own copied
    // value buffer, which lead to multiple places when the same data
    // was stored (if a child had its data, then its parent had it too +
    // their own, etc.)
    // Now, there's only a single instance of this buffer and each
    // object holds its pointer, as well as its own data start offset
    // and length
    class ASN1ObjectData {
    protected:
        std::shared_ptr<std::vector<uint8_t>> _buffer; // buffer holding binary data of related ASN1Object module (tree)
        size_t _value_offset; // offset from the start of _buffer to the start of this object's value
        size_t _value_size; // size of this object's value

    public:
        // This constructor copies an already existing ASN1ObjectData (already existing buffer vector)
        ASN1ObjectData(std::shared_ptr<std::vector<uint8_t>> buffer,
        size_t _value_offset,
        size_t _value_size) : 
        _buffer(buffer),
        _value_offset(_value_offset),
        _value_size(_value_size) {}

        // This constructor creates a buffer vector and makes sure it gets zero'ed when dropped
        // Note: as the buffer vector should be held only in this object, the constructor takes
        // an rvalue (move instead of copy)
        ASN1ObjectData(std::vector<uint8_t> &&buffer,
        size_t _value_offset,
        size_t _value_size) : 
        _buffer(std::shared_ptr<std::vector<uint8_t>>(
            new std::vector<uint8_t>(std::move(buffer)), 
            secure_delete_vector
        )),
        _value_offset(_value_offset),
        _value_size(_value_size) {}

        inline const std::shared_ptr<std::vector<uint8_t>> buffer() const {
            return _buffer;
        }

        inline size_t value_offset() const {
            return _value_offset;
        }

        inline size_t value_size() const {
            return _value_size;
        }
    };

    // Class representing an ASN.1 object - contains a tag (see ASN1Tag above),
    // raw value and children, if parsed recursively
    class ASN1Object {
    protected:
        ASN1Tag _tag; // ASN.1 tag
        size_t _tag_length_size; // Size of tag+length fields (in bytes)
        //std::vector<uint8_t> _value; // Value bytes
        ASN1ObjectData _object_data; // Value data wrapper
        std::vector<std::shared_ptr<ASN1Object>> _children; // Set of child objects (1 level deep); empty if there're no children

    public:
        // Creates an ASN1Object, initializes its fields and optionally prints a debug message
        ASN1Object(ASN1Tag tag, size_t tag_length_size, ASN1ObjectData object_data) :
        _tag(tag), _tag_length_size(tag_length_size), _object_data(object_data) {
            #ifdef ASN1_DEBUG
            std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                << std::dec << ", value_size=" << _object_data.value_size() << std::endl;
            #endif // ASN1_DEBUG
        }

        // Creates an ASN1Object for encoding purposes, taking only tag and value vector
        // (as an rvalue, for secure memory managing)
        ASN1Object(ASN1Tag tag, std::vector<uint8_t> &&value) :
        _tag(tag), _object_data(ASN1ObjectData(
            std::shared_ptr<std::vector<uint8_t>>(
                new std::vector<uint8_t>(std::move(value)), 
                secure_delete_vector
            ), 0, value.size()
        )) {
            #ifdef ASN1_DEBUG
            std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                << std::dec << ", value_size=" << _object_data.value_size() << std::endl;
            #endif // ASN1_DEBUG
        }

        // Destroys an ASN1Object and optionally prints a debug message
        ~ASN1Object() {
            #ifdef ASN1_DEBUG
            std::cerr << "[ASN1Object] ASN1Object destroyed: tag=" << std::hex << static_cast<int>(_tag)
                << ", value_size=" << _object_data.value_size() << std::endl;
            #endif // ASN1_DEBUG
        }

        // returns object's tag
        inline ASN1Tag tag() const {
            return _tag;
        }

        // returns object's total size (in bytes) - that sums up the tag field size, 
        // length field size and the size of a value buffer
        inline size_t total_size() const {
            return _tag_length_size + _object_data.value_size();
        }

        // return's object's value buffer (read-only)
        inline const ASN1ObjectData object_data() const {
            return _object_data;
        }

        // returns object's children (read-only)
        inline const std::vector<std::shared_ptr<ASN1Object>>& children() const {
            return _children;
        }

        // Prints the ASN.1 tree in readable format - function prototype, most probably
        // won't be used so I don't really care about it
        void print(int = 0);

        // friends may take what's protected stuff instead of asking for it
        // those friends need to be able to push elements inside the _children vector
        friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::vector<uint8_t> &&data, size_t offset);
        friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::shared_ptr<std::vector<uint8_t>> data, size_t offset);
        friend bool RSA::_RSAPrivateKey_format_check(std::shared_ptr<ASN1Object> root_object);
    };


    // Responsible for encoding/decoding ASN.1 OBJECT IDENTIFIER objects
    class ASN1ObjectIdentifier : public ASN1Object{
    public:
        // Returns the ASN.1 OBJECT IDENTIFIER object value as a readable string (instead of default buffer)
        inline const std::string value() const {
            return decode(_object_data);
        }

        // The ASN.1 OBJECT IDENTIFIER encoder - returns a binary representation
        // of OBJECT IDENTIFIER (as a buffer)
        //
        // Input:
        // @obj_id_str - OBJECT IDENTIFIER as a string (eg. "1.23.4567.89.0")
        static std::vector<uint8_t> encode(std::string const &obj_id_str);

        // ASN.1 OBJECT IDENTIFIER decoder - outputs a string (eg. "1.23.4567.89.0")
        //
        // Input:
        // @obj_id_data - ASN1ObjectData containing the OBJECT IDENTIFIER
        static std::string decode(ASN1ObjectData data);
    };

    // Responsible for encoding/decoding ASN.1 INTEGER objects
    class ASN1Integer : public ASN1Object {
    public:
        // Returns the ASN.1 INTEGER object value as GMP integer (instead of default buffer)
        inline const mpz_class value() const {
            return decode(_object_data);
        }

        // Encodes a GMP integer to the binary form, big-endian (ANS.1 compatibile), returning a buffer
        //
        // Input:
        // @num - GMP integer to encode
        static std::vector<uint8_t> encode(mpz_class const &num);

        // Decodes a buffer holding binary data into a GMP integer and returns it
        //
        // Input:
        // @data - ASN1ObjectData containing the integer
        static mpz_class decode(ASN1ObjectData data);
    };

    // // ASN1ObjectIdentifier helper functions
    std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer);
    mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::reverse_iterator rb, std::vector<uint8_t>::reverse_iterator re);
}