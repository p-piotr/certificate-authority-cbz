#pragma once

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <span>
#include <gmpxx.h>
#include "utils/security.hpp"

namespace CBZ {

    // Question: why is ASN1 namespace declared 2 times + RSA namespace declaration in the middle of ASN1?
    // Answer: https://en.wikipedia.org/wiki/Circular_dependency

    // This namespace is defined in fully defined later on - forward declaration of ASN1Object for the function down below in the RSA namespace
    namespace ASN1 { class ASN1Object; }

    // This namespace is defined in "private_key.h" and "pkcs.h" - forward declaration of a function used as a friend in ASN1Object
    namespace PKCS {
        int _RSAPrivateKey_check_and_expand(
            ASN1::ASN1Object& root_object
        );
    }

    namespace ASN1 {

        // Chosen set of ASN.1 tags
        enum ASN1Tag {
            ANY = 0x00,
            INTEGER = 0x02,
            BIT_STRING = 0x03,
            OCTET_STRING = 0x04,
            NULL_TYPE = 0x05,
            OBJECT_IDENTIFIER = 0x06,
            UTF8_STRING = 0x0C,
            PRINTABLE_STRING = 0x13,
            IA5_STRING = 0x16,
            UTC_TIME = 0x17,
            GENERALIZED_TIME = 0x18,
            SEQUENCE = 0x30,
            SET = 0x31,
            CONSTRUCTED_TYPE = 0xA0,
        };

        // Converts an ASN.1 tag (enum) to string
        const char* tag_to_string(ASN1Tag tag);

        // Look for definition below
        class ASN1Object;

        namespace _ASN1_helpers {
            // Calculates the size of 'length' field based on provided size
            //
            // Input:
            // @size - size of object's data, in bytes
            static size_t _ASN1Object_calculate_length_field_size(size_t size);

            // This function takes size of object's data and returns an encoded length field
            //
            // Input:
            // @size - size of object's data, in bytes
            static std::vector<uint8_t> _ASN1Object_encode_length_field(size_t size);

            // // ASN1ObjectIdentifier helper functions
            std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer);
            mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::reverse_iterator rb, std::vector<uint8_t>::reverse_iterator re);
        };

        // Responsible for parsing ASN.1
        class ASN1Parser {
        public:
            // This function encodes a singular ASN.1 object into binary form
            // Note: this function can only encode an object with value set, otherwise
            // it throws an exception
            //
            // Input:
            // @object - ASN1Object to encode
            static std::vector<uint8_t> encode(ASN1Object const& object);

            // This function encodes an ASN.1 object (and its children recursively) into binary form
            // returning a byte vector
            //
            // Input:
            // @root_object - root ASN1Object to encode
            static std::vector<uint8_t> encode_all(ASN1Object const& root_object);

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
            //               no children (for performance)
            static ASN1Object decode(
                std::vector<uint8_t> const& data, 
                size_t offset, 
                bool copy_value
            );

            // Parses ASN.1 binary data recursively to create a module tree, returning the root element
            //
            // Input:
            // @data - shared pointer to byte vector containing ASN.1 binary data 
            // as an rvalue - this buffer will be managed by ASN1Object instances 
            // and safely destroyed when no longer needed (memory zeroed before deallocation)
            // @offset - offset in @data to start from
            static ASN1Object decode_all(std::vector<uint8_t> const& data, size_t offset=0);

            // The ASN.1 OBJECT IDENTIFIER encoder - returns a binary representation
            // of OBJECT IDENTIFIER (as a buffer)
            //
            // Input:
            // @obj_id_str - OBJECT IDENTIFIER as a string (eg. "1.23.4567.89.0")
            static std::vector<uint8_t> object_identifier_encode(const std::string& obj_id_str);

            // ASN.1 OBJECT IDENTIFIER decoder - outputs a string (eg. "1.23.4567.89.0")
            //
            // Input:
            // @obj_id_data - ASN1ObjectData containing the OBJECT IDENTIFIER
            static std::string object_identifier_decode(const std::vector<uint8_t>& data);

            // Encodes a GMP integer to the binary form, big-endian (ANS.1 compatibile), returning a buffer
            //
            // Input:
            // @num - GMP integer to encode
            static std::vector<uint8_t> integer_encode(const mpz_class& num);

            // Decodes a buffer holding binary data into a GMP integer and returns it
            //
            // Input:
            // @data - ASN1ObjectData containing the integer
            static mpz_class integer_decode(const std::vector<uint8_t>& data);

            ASN1Parser() = delete;
            ~ASN1Parser() = delete;
        };
        
        // Class representing an ASN.1 object - contains a tag (see ASN1Tag above),
        // raw value and children, if parsed recursively
        class ASN1Object {
        protected:
            ASN1Tag _tag;                           // ASN.1 tag
            size_t _length;                         // ASN.1 length
            std::vector<uint8_t> _value;            // ASN.1 value
            std::vector<ASN1Object> _children;      // Set of child objects (1 level deep); empty if there're no children
            std::vector<uint8_t> _encoded;          // Buffer holding this object, ASN.1 encoded - used as a cache for multiple
                                                    // comparisons during sorting process, e.g. while constructing an ASN.1 set

        public:
            explicit ASN1Object(
                ASN1Tag tag
            );
            explicit ASN1Object(
                ASN1Tag tag,
                size_t length
            );
            explicit ASN1Object(
                ASN1Tag tag,
                std::vector<uint8_t> value
            );
            explicit ASN1Object(
                ASN1Tag tag,
                std::string value
            );
            explicit ASN1Object(
                ASN1Tag tag,
                std::vector<ASN1Object>&& children
            );
            ASN1Object(
                ASN1Object&& r
            ) noexcept;
            ASN1Object(const ASN1Object& r) = default;

            virtual ~ASN1Object();

            // overloaded operators
            // needed when sorting vectors consisting of ASN1Object instances,
            // e.g. when forming an ASN.1 set

            // the only reason this isn't marked as const is because
            // the _encoded cache may be set if hadn't been set already
            bool operator<(ASN1Object& other) noexcept;
            ASN1Object& operator=(const ASN1Object& other) noexcept = default;
            ASN1Object& operator=(ASN1Object&& other) noexcept = default;

            // Returns object's tag
            inline ASN1Tag tag() const {
                return _tag;
            }

            // Returns object's length (value in 'length' field)
            inline size_t length() const {
                return _length;
            }

            // Returns object's encoded 'length' field
            inline std::vector<uint8_t> encode_length() const {
                return _ASN1_helpers::_ASN1Object_encode_length_field(_length);
            }

            // Returns object's encoded 'length' field size, in bytes (without encoding it)
            inline size_t length_size() const {
                return _ASN1_helpers::_ASN1Object_calculate_length_field_size(_length);
            }

            // Returns object's total size (in bytes) - that sums up the 'tag' field size, 
            // 'length' field size and the size of a value buffer
            inline size_t total_size() const {
                return 1 + length_size() + _length;
            }

            // Returns object's value vector (immutable reference)
            inline const std::vector<uint8_t>& value() const {
                return _value;
            }

            // Returns object's value vector (modifiable reference)
            inline std::vector<uint8_t>& value() {
                return _value;
            }

            // returns object's children (read-only)
            inline const std::vector<ASN1Object>& children() const {
                return _children;
            }

            // Prints the ASN.1 tree in readable format - function prototype, most probably
            // won't be used so I don't really care about it
            void print(int = 0) const;

            inline std::vector<uint8_t> encode() const {
                return ASN1Parser::encode_all(*this);
            }

            static inline ASN1Object decode(const std::vector<uint8_t>& data, size_t offset = 0) {
                return ASN1Parser::decode_all(data, offset);
            }

            // friends may take what's protected stuff instead of asking for it
            // those friends need to be able to change the internal state of ASN1Object

            friend class ASN1Parser;
            friend int PKCS::_RSAPrivateKey_check_and_expand(
                ASN1Object& root_object
            );
        };


        // Responsible for encoding/decoding ASN.1 OBJECT IDENTIFIER objects
        class ASN1ObjectIdentifier : public ASN1Object{
        public:
            explicit ASN1ObjectIdentifier(const std::string& oid)
                : ASN1Object(OBJECT_IDENTIFIER, ASN1Parser::object_identifier_encode(oid)) {}

            explicit ASN1ObjectIdentifier(const ASN1Object& object)
                : ASN1Object(std::move(object))
            {
                if (this->tag() != OBJECT_IDENTIFIER)
                    throw std::runtime_error("[ASN1ObjectIdentifier::ASN1ObjectIdentifier] object does not have OBJECT_IDENTIFIER tag");
            }

            // Returns the ASN.1 OBJECT IDENTIFIER object value as a readable string (instead of default buffer)
            inline std::string const value() const {
                return ASN1Parser::object_identifier_decode(_value);
            }

            static inline ASN1ObjectIdentifier decode(const std::vector<uint8_t>& data, size_t offset = 0) {
                return ASN1ObjectIdentifier(ASN1Object::decode(std::move(data), offset));
            }
        };

        // Responsible for encoding/decoding ASN.1 INTEGER objects
        class ASN1Integer : public ASN1Object {
        public:
            explicit ASN1Integer(const mpz_class& num)
                : ASN1Object(INTEGER, ASN1Parser::integer_encode(num)) {}

            explicit ASN1Integer(int num)
                : ASN1Integer(mpz_class(num)) {}
            
            explicit ASN1Integer(const std::string& num)
                : ASN1Integer(mpz_class(std::move(num))) {}

            explicit ASN1Integer(const ASN1Object& object)
                : ASN1Object(std::move(object))
            {
                if (this->tag() != INTEGER)
                    throw std::runtime_error("[ASN1Integer::ASN1Integer] object does not have INTEGER tag");
            }

            // Returns the ASN.1 INTEGER object value as GMP integer (instead of default buffer)
            inline mpz_class const value() const {
                return ASN1Parser::integer_decode(_value);
            }

            static inline ASN1Integer decode(const std::vector<uint8_t>& data, size_t offset = 0) {
                return ASN1Integer(ASN1Object::decode(std::move(data), offset));
            }
        };

        class ASN1Sequence : public ASN1Object {
        public:
            explicit ASN1Sequence(std::vector<ASN1Object> children)
                : ASN1Object(SEQUENCE, std::move(children)) {}
        };

        class ASN1Null : public ASN1Object {
        public:
            explicit ASN1Null()
                : ASN1Object(NULL_TYPE) {}
        };

        class ASN1BitString : public ASN1Object {
        public:
            explicit ASN1BitString(std::vector<uint8_t> s, int unused = 0);
        };

        class ASN1OctetString : public ASN1Object {
        public:
            explicit ASN1OctetString(std::vector<uint8_t> s)
                : ASN1Object(OCTET_STRING, std::move(s)) {}
        };

        class ASN1String : public ASN1Object {
        public:
            explicit ASN1String(ASN1Tag string_tag, std::string s);
        };

        class ASN1Set : public ASN1Object {
        private:
            static inline std::vector<ASN1Object> set_sort(std::vector<ASN1Object> v) {
                std::sort(v.begin(), v.end());
                return v;
            }

        public:
            explicit ASN1Set(std::vector<ASN1Object> children)
                : ASN1Object(SET, set_sort(std::move(children))) {}
        };
    }
}
