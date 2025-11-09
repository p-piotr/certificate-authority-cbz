#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <gmpxx.h>
#include "debug.h"
#include "security.h"

namespace CBZ {

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
            // This function encodes a singular ASN.1 object into binary form
            // Note: this function can only encode an object with value set, otherwise
            // it throws an exception
            //
            // Input:
            // @object - ASN1Object to encode
            static std::shared_ptr<std::vector<uint8_t>> encode(std::shared_ptr<ASN1Object> object);

            // This function encodes an ASN.1 object (and its children recursively) into binary form
            // returning a byte vector
            //
            // Input:
            // @root_object - root ASN1Object to encode
            static std::shared_ptr<std::vector<uint8_t>> encode_all(std::shared_ptr<ASN1Object> root_object);

            // This function parses ASN.1 binary data and returns a parsed element 
            // (does not parse recursively - see ASN1Parser::decode_all)
            // If copy_value is set, _tag + _length + _value are returned
            // If it is not set, only _tag + _length are returned
            //
            // Input:
            // @data - byte vector containing ASN.1 binary data
            // @offset - offset from the beginning of @data from which parsing should be started
            // @copy_value - boolean specifying if data is to be copied to the returned 
            //               object - set to "true" only if you know the object has 
            //               no children for performance
            static std::shared_ptr<ASN1Object> decode(
                std::shared_ptr<std::vector<uint8_t>> data, 
                size_t offset, 
                bool copy_value
            );

            // Parses ASN.1 binary data recursively to create a module tree, returning the root element
            //
            // Input:
            // @data - shared pointer to byte vector containing ASN.1 binary data 
            // as an rvalue - this buffer will be managed by ASN1ObjectData instances 
            // and safely destroyed when no longer needed (memory zeroed before deallocation)
            // @offset - offset in @data to start from
            static std::shared_ptr<ASN1Object> decode_all(std::vector<uint8_t> &&data, size_t offset=0);

            // Parses ASN.1 binary data recursively to create a module tree, returning the root element
            // This function operates on an already created shared pointer to a byte vector
            //
            // Input:
            // @data - shared pointer to byte vector containing ASN.1 binary data
            // @offset - offset in @data to start from
            static std::shared_ptr<ASN1Object> decode_all(std::shared_ptr<std::vector<uint8_t>> data, size_t offset=0);

            // Converts an ASN.1 tag (enum) to string
            static const char* tag_to_string(ASN1Tag tag);

            // Calculates the size of 'length' field based on provided size
            //
            // Input:
            // @size - size of object's data, in bytes
            static size_t _ASN1Parser_calculate_length_field_size(size_t size);

            // This function takes size of object's data and returns an encoded length field
            //
            // Input:
            // @size - size of object's data, in bytes
            static std::vector<uint8_t> _ASN1Parser_encode_length_field(size_t size);
        };

        // Class representing an ASN.1 object - contains a tag (see ASN1Tag above),
        // raw value and children, if parsed recursively
        class ASN1Object {
        protected:
            ASN1Tag _tag; // ASN.1 tag
            size_t _length; // ASN.1 length
            std::vector<uint8_t> _value; // ASN.1 value
            std::vector<std::shared_ptr<ASN1Object>> _children; // Set of child objects (1 level deep); empty if there're no children

        public:
            ASN1Object(ASN1Tag tag) :
            _tag(tag),
            _length(0) {
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                    << std::dec << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            ASN1Object(ASN1Tag tag, size_t length) :
            _tag(tag),
            _length(length) {
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                    << std::dec << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            // take value by const-reference to avoid overload ambiguity with the rvalue overload
            ASN1Object(ASN1Tag tag, const std::vector<uint8_t>& value) :
            _tag(tag),
            _length(value.size()),
            _value(value) {
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                    << std::dec << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            ASN1Object(ASN1Tag tag, std::vector<uint8_t> &&value) :
            _tag(tag), 
            _length(value.size()),
            _value(std::move(value)
            ) {
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                    << std::dec << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            ASN1Object(ASN1Tag tag, std::vector<std::shared_ptr<ASN1Object>> &&children) :
            _tag(tag), 
            _children(std::move(children)) {
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << static_cast<int>(_tag) 
                    << std::dec << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            ~ASN1Object() {
                secure_zero_memory(_value.data(), _value.size()); // don't forget to zero data as it may be critical
                #ifdef ASN1_DEBUG
                std::cerr << "[ASN1Object] ASN1Object destroyed: tag=" << std::hex << static_cast<int>(_tag)
                    << ", value_size=" << _value.size() << std::endl;
                #endif // ASN1_DEBUG
            }

            // Returns object's tag
            constexpr ASN1Tag tag() const {
                return _tag;
            }

            // Returns object's length (value in 'length' field)
            constexpr size_t length() const {
                return _length;
            }

            // Returns object's encoded 'length' field
            inline std::vector<uint8_t> encode_length() const {
                return ASN1Parser::_ASN1Parser_encode_length_field(_length);
            }

            // Returns object's encoded 'length' field size, in bytes (without encoding it)
            inline size_t length_size() const {
                return ASN1Parser::_ASN1Parser_calculate_length_field_size(_length);
            }

            // Returns object's total size (in bytes) - that sums up the 'tag' field size, 
            // 'length' field size and the size of a value buffer
            inline size_t total_size() const {
                return 1 + length_size() + _length;
            }

            // Returns object's value vector (modifiable reference)
            constexpr std::vector<uint8_t>& value() {
                return _value;
            }

            // returns object's children (read-only)
            constexpr const std::vector<std::shared_ptr<ASN1Object>>& children() const {
                return _children;
            }

            // Prints the ASN.1 tree in readable format - function prototype, most probably
            // won't be used so I don't really care about it
            void print(int = 0);


            // friends may take what's protected stuff instead of asking for it
            // those friends need to be able to change the internal state of ASN1Object
            friend std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode(
                std::shared_ptr<ASN1Object> object
            );
            friend std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode_all(
                std::shared_ptr<ASN1Object> root_object
            );
            friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(
                std::vector<uint8_t> &&data, 
                size_t offset
            );
            friend std::shared_ptr<ASN1Object> ASN1Parser::decode_all(
                std::shared_ptr<std::vector<uint8_t>> data, 
                size_t offset
            );
            friend bool RSA::_RSAPrivateKey_format_check(
                std::shared_ptr<ASN1Object> root_object
            );
        };


        // Responsible for encoding/decoding ASN.1 OBJECT IDENTIFIER objects
        class ASN1ObjectIdentifier : public ASN1Object{
        public:
            // Returns the ASN.1 OBJECT IDENTIFIER object value as a readable string (instead of default buffer)
            inline const std::string value() const {
                return decode(_value);
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
            static std::string decode(std::vector<uint8_t> const &data);
        };

        // Responsible for encoding/decoding ASN.1 INTEGER objects
        class ASN1Integer : public ASN1Object {
        public:
            // Returns the ASN.1 INTEGER object value as GMP integer (instead of default buffer)
            inline const mpz_class value() const {
                return decode(_value);
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
            static mpz_class decode(std::vector<uint8_t> const &data);
        };

        // // ASN1ObjectIdentifier helper functions
        std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer);
        mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::reverse_iterator rb, std::vector<uint8_t>::reverse_iterator re);
    }
}