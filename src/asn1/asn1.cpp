#include <vector>
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <memory>
#include <iostream>
#include <gmpxx.h>
#include <cctype>
#include <sstream>
#include "asn1/asn1.h"
#include "utils/security.hpp"

// This namespace contains all functionality related to ASN1
namespace CBZ::ASN1 {

    using namespace CBZ::Security;

    // Converts an ASN.1 tag (enum) to string
    const char* tag_to_string(ASN1Tag tag) {
        switch (tag) {
            case (INTEGER): return "INTEGER";
            case (BIT_STRING): return "BIT_STRING";
            case (OCTET_STRING): return "OCTET_STRING";
            case (NULL_TYPE): return "NULL";
            case (OBJECT_IDENTIFIER): return "OBJECT_IDENTIFIER";
            case (UTF8_STRING): return "UTF8_STRING";
            case (SEQUENCE): return "SEQUENCE";
            case (SET): return "SET";
            case (PRINTABLE_STRING): return "PRINTABLE_STRING";
            case (IA5_STRING): return "IA5_STRING";
            case (UTC_TIME): return "UTC_TIME";
            case (GENERALIZED_TIME): return "GENERALIZED_TIME";
            default: return "undefined";
        }
    }

    std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode(ASN1Object const& object) {
        // first, check whether it's NULL if it doesn't have neither value nor children
        if (
            object.value().size() == 0 
            && object.children().size() != 0 
            && object.tag() != ASN1Tag::NULL_TYPE
        )
            throw std::runtime_error("[ASN1Parser::encode] Can't encode a non-NULL object that has NULL properties");

        std::vector<uint8_t> encoded_object, encoded_length;
        // append tag
        encoded_object.push_back(static_cast<uint8_t>(object.tag()));
        // append length
        encoded_length = object.encode_length();
        encoded_object.insert(
            encoded_object.end(),
            encoded_length.cbegin(),
            encoded_length.cend()
        );
        // append value
        encoded_object.insert(
            encoded_object.end(),
            object.value().begin(),
            object.value().end()
        );

        return std::shared_ptr<std::vector<uint8_t>>(
            new std::vector<uint8_t>(std::move(encoded_object)), 
            secure_delete<std::vector<uint8_t>>
        );
    }

    std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode_all(ASN1Object const& root_object) {
        bool has_children = !root_object.children().empty();
        bool has_value = root_object.value().size() > 0;
        if (has_children && has_value)
            // the object cannot have value and children at the same time
            throw std::runtime_error("[ASN1Parser::encode_all] ASN.1 Object must have either children or value, or none"); // (NULL can have none)

        if (has_value || (!has_value && !has_children))
            // if the object has a value, or doesn't have value nor children, encode it directly
            return encode(root_object);

        // the object has children - encode them first
        std::vector<std::shared_ptr<std::vector<uint8_t>>> encoded_children;
        for (std::shared_ptr<ASN1Object> child : root_object.children())
            encoded_children.push_back(encode_all(*child));

        // concatenate root object tag, length and encoded children
        std::vector<uint8_t> encoded_root_object;
        encoded_root_object.push_back(static_cast<uint8_t>(root_object.tag()));
        // calculate total size of children
        size_t total_children_size = 0;
        for (auto child_data : encoded_children)
            total_children_size += child_data->size();

        // since the object has children, we need to encode the length field accordingly
        std::vector<uint8_t> length_field = _ASN1_helpers::_ASN1Object_encode_length_field(total_children_size);
        // append length field
        encoded_root_object.insert(
            encoded_root_object.end(),
            length_field.cbegin(),
            length_field.cend()
        );
        // append encoded children
        for (auto child_data : encoded_children) {
            size_t current_offset = encoded_root_object.size();
            encoded_root_object.insert(
                encoded_root_object.end(),
                child_data->cbegin(),
                child_data->cend()
            );
        }

        return std::shared_ptr<std::vector<uint8_t>>(
            new std::vector<uint8_t>(std::move(encoded_root_object)),
            secure_delete<std::vector<uint8_t>>
        );
    }

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
    std::shared_ptr<ASN1Object> ASN1Parser::decode(
        std::vector<uint8_t> const& data, 
        size_t offset,
        bool copy_value
    ) {
        // Check if offset doesn't go out of bounds
        if (offset >= data.size())
            throw std::runtime_error("[ASN1Parser::decode] Offset out of bounds");

        ASN1Tag tag = static_cast<ASN1Tag>(data[offset++]);
        // Again, check if the new offset doesn't go out of bounds
        if (offset >= data.size())
            throw std::runtime_error("[ASN1Parser::decode] Incomplete ASN.1 data");

        // Calculate length - if MSB is set, length is specified in the long form
        size_t length = data[offset++];
        if (length  & 0x80) { // Long form, decode it
            size_t num_bytes = length  & 0x7F;
            if (num_bytes == 0 || num_bytes > sizeof(size_t) || offset + num_bytes > data.size())
                throw std::runtime_error("[ASN1Parser::decode] Invalid length encoding");

            length = 0;
            for (size_t i = 0; i < num_bytes; ++i)
                length = (length << 8) | data[offset++];
        }

        // Check if the calculated value doesn't go out of bounds
        if (offset + length > data.size())
            throw std::runtime_error("[ASN1Parser::decode] Incomplete ASN.1 data (out of bounds)");

        std::shared_ptr<ASN1Object> obj;

        if (copy_value) {
            // Copy the value vector from data,
            std::vector<uint8_t> value(data.begin() + offset, data.begin() + offset + length);
            // and return it in the new object
            obj = std::make_shared<ASN1Object>(tag, std::move(value));
        }
        else {
            // Only set the tag and length
            obj = std::make_shared<ASN1Object>(tag, length);
        }
        return obj;
    }

    // Parses ASN.1 binary data recursively to create a module tree, returning the root element
    // See asn1.h for details
    // Input:
    // @data - byte vector containing ASN.1 binary data
    // @offset - offset in @data to start from
    std::shared_ptr<ASN1Object> ASN1Parser::decode_all(
        std::vector<uint8_t> const& data, 
        size_t offset
    ) {
        uint8_t tag = data[offset];
        if (!(tag  & 0x20)) // 6th bit is not set - object is "primitive" => doesn't contain children
            return decode(data, offset, true);

        // else, the object contains children - we must decode them
        auto root_object = decode(data, offset, false);
        offset += (1 + root_object->length_size());
        size_t offset_t = offset;
        while (offset_t < offset + root_object->length()) {
            auto child_object = decode_all(data, offset_t);
            root_object->_children.push_back(child_object);
            offset_t += child_object->total_size();
        }
        // check if final offset matches root object's length - if not,
        // something's wrong - buffer is probably corrupted
        if (offset_t != offset + root_object->length())
            throw std::runtime_error("[ASN1Parser::decode_all] final offset doesn't match calculated length - possible buffer corruption");

        return root_object;
    }

    // Converts a vector holding ASN1Object instances to a vector holding smart pointers holding those ASN1Object instances
    std::vector<std::shared_ptr<ASN1Object>> ASN1Object::convert_to_shared(std::vector<ASN1Object>&& input) {
        std::vector<std::shared_ptr<ASN1Object>> output;
        output.reserve(input.size());
        for (auto& item : input)
            output.push_back(std::make_shared<ASN1Object>(std::move(item)));
        return output;
    }

    ASN1Object::ASN1Object(ASN1Tag tag) :
        _tag(tag),
        _length(0) {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object created: tag=" << tag_to_string(_tag) 
            << std::dec << ", value_size=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

    ASN1Object::ASN1Object(ASN1Tag tag, size_t length) :
        _tag(tag),
        _length(length) {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object created: tag=" << tag_to_string(_tag) 
            << std::dec << ", value_size=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

    // take value by const-reference to avoid overload ambiguity with the rvalue overload
    // NOT RELEVANT ANYMORE I GUESS THAT'S MORE UNIVERSAL
    ASN1Object::ASN1Object(ASN1Tag tag, std::vector<uint8_t> value) :
        _tag(tag),
        _length(value.size()),
        _value(std::move(value)) {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object created: tag=" << tag_to_string(_tag) 
            << std::dec << ", value_size=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

    ASN1Object::ASN1Object(ASN1Tag tag, std::vector<ASN1Object>&& children)
        : ASN1Object(tag, convert_to_shared(std::move(children))) {}

    ASN1Object::ASN1Object(ASN1Tag tag, std::vector<std::shared_ptr<ASN1Object>>&& children) :
        _tag(tag), 
        _children(std::move(children)) {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object created: tag=" << tag_to_string(_tag) 
            << std::dec << ", value_size=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

    ASN1Object::~ASN1Object() {
        CBZ::Security::secure_zero_memory(_value); // don't forget to zero data as it may be critical
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object destroyed: tag=" << tag_to_string(_tag) 
            << ", value_size=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }


    // Converts an ASN.1 tag (enum) to string
    void ASN1Object::print(int indent) {
        std::string output = "";
        for (int i = 0; i < indent; i++)
            output += '\t';

        output += "TYPE: ";
        output += tag_to_string(_tag);
        // output value in format depending on the tag
        std::cout << output << std::endl;
        for (auto child : _children)
            child->print(indent+1);        
    }

    size_t _ASN1_helpers::_ASN1Object_calculate_length_field_size(size_t length) {
        if (length < 128)
            // short form
            return 1;

        // long form
        size_t num_bytes = 0;
        while (length > 0) {
            num_bytes++;
            length >>= 8;
        }
        return 1 + num_bytes;
    }

    std::vector<uint8_t> _ASN1_helpers::_ASN1Object_encode_length_field(size_t length) {
        std::vector<uint8_t> length_field;
        if (length < 128) {
            // short form
            length_field = { static_cast<uint8_t>(length) };
            return length_field;
        }
        // long form
        size_t num_bytes = _ASN1_helpers::_ASN1Object_calculate_length_field_size(length) - 1;
        length_field.push_back(static_cast<uint8_t>(0x80 | num_bytes));

        for (size_t i = num_bytes; i > 0; i--)
            length_field.push_back(static_cast<uint8_t>((length >> ((i - 1) * 8)) & 0xFF));

        return length_field;
    }

    // Helper for ASN1ObjectIdentifier::encode - encodes a single GMP integer
    // into ASN.1 OBJECT IDENTIFIER format, returning a byte vector
    // containing the integer's ASN.1 OBJECT IDENTIFIER representation
    // See: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#object-identifier-encoding
    // Input:
    // @integer - GMP integer to convert
    std::vector<uint8_t> _ASN1ObjectIdentifier_encode_single_integer(mpz_class integer) {
        std::vector<uint8_t> result;
        std::vector<uint8_t> remainders;

        while (integer > 127) {
            remainders.push_back(static_cast<uint8_t>(mpz_class(integer % 128).get_ui()));
            integer /= 128;
        }
        remainders.push_back(static_cast<uint8_t>(integer.get_ui()));

        auto it = remainders.rbegin();
        for (it; it != --remainders.rend(); it++)
            result.push_back(*it | 0x80);

        result.push_back(*it);
        return result;
    }

    // Helper for ASN1ObjectIdentifier::decode - decodes a single OBJECT IDENTIFIER integer, returning a GMP integer
    // Input:
    // @rb - constant reverse iterator pointing at the last element of the encoded integer's vector
    // @re - constant reverse iterator pointing at the element before the first one of the encoded integer's vector
    mpz_class _ASN1ObjectIdentifier_decode_single_integer(
        std::vector<uint8_t>::const_reverse_iterator rb, 
        std::vector<uint8_t>::const_reverse_iterator re
    ) {
        mpz_class result = 0;
        mpz_class multiplier = 1;
        for (auto it = rb; it != re; it++) {
            result += (*it & 0x7F) * multiplier;
            multiplier *= 128;
        }

        return result;
    }

    // The ASN.1 OBJECT IDENTIFIER encoder - returns a binary representation of OBJECT IDENTIFIER (as a buffer)
    // Input:
    // @obj_id_str - OBJECT IDENTIFIER as a string (eg. "1.23.4567.89.0")
    std::vector<uint8_t> ASN1ObjectIdentifier::encode(std::string const& obj_id_str) {
        std::vector<mpz_class> integers; // holds the parsed integers from obj_id_str, eg. "1.23.4567.89.0" -> [1, 23, 4567, 89, 0]
        std::vector<uint8_t> result;
        std::string temp = ""; // temporary string holding digits of the current integer being parsed

        for (char ch : obj_id_str) {
            // parse the string into integers
            if (ch == '.') {
                if (temp.size() == 0) // two dots in a row or dot at the beginning
                    throw std::runtime_error("[ASN1ObjectIdentifier::encode] Invalid format of ASN.1 Object Identifier");

                // convert the parsed integer string to GMP integer and store it
                integers.push_back(mpz_class(temp));
                temp = "";
            }
            else if (std::isdigit(ch))
                temp += ch;
            else // illegal character
                throw std::runtime_error("[ASN1ObjectIdentifier::encode] Invalid character in ASN.1 Object Identifier");
        }
        if (temp.size() > 0) // append the last integer, since it won't be followed by a dot
            integers.push_back(mpz_class(temp));

        // encode the whole OBJECT IDENTIFIER acording to https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/#object-identifier-encoding
        auto it = integers.begin();
        mpz_class integer = *it++ * 40;
        integer += *it++;
        std::vector<uint8_t> enc_integer = _ASN1ObjectIdentifier_encode_single_integer(integer);
        result.insert(result.end(), enc_integer.begin(), enc_integer.end());

        while (it != integers.end()) {
            integer = *it++;
            enc_integer = _ASN1ObjectIdentifier_encode_single_integer(integer);
            result.insert(result.end(), enc_integer.begin(), enc_integer.end());
        }

        return result;
    }

    // ASN.1 OBJECT IDENTIFIER decoder - outputs a string (eg. "1.23.4567.89.0")
    // Input:
    // @obj_id - vector containing binary representatoin of the OBJECT IDENTIFIER
    std::string ASN1ObjectIdentifier::decode(std::vector<uint8_t> const& data) {
        std::string integer_str;
        std::string result = "";
        auto rb = data.crbegin();
        auto re = rb + 1;

        // parse (from the end to the beginning), till the first two integers
        while (re != data.crend()) {
            if (*re  & 0x80) { // MSB set - continue
                re++;
                continue;
            }
            // decode single integer and prepend it to the result string
            integer_str = _ASN1ObjectIdentifier_decode_single_integer(rb, re).get_str();
            result.insert(result.cbegin(), integer_str.begin(), integer_str.end());
            result.insert(result.cbegin(), '.');
            rb = re;
            re = rb + 1;
        }

        // decode the first two integers
        mpz_class double_integer = _ASN1ObjectIdentifier_decode_single_integer(rb, re);
        mpz_class x;
        mpz_class y;
        if (double_integer < 40) { // x = 0
            x = 0;
            y = double_integer;
        }
        else if (double_integer < 80) { // x = 1
            x = 1;
            y = double_integer - 40;
        }
        else { // x = 2
            x = 2;
            y = double_integer - 80;
        }
        // prepend x and y to the result string
        std::string x_str = x.get_str();
        std::string y_str = y.get_str();
        result.insert(result.cbegin(), y_str.begin(), y_str.end());
        result.insert(result.cbegin(), '.');
        result.insert(result.cbegin(), x_str.begin(), x_str.end());

        return result;
    }

    // Encodes a GMP integer to the binary form, big-endian (ANS.1 compatibile), returning a buffer
    // Input:
    // @num - GMP integer to encode
    std::vector<uint8_t> ASN1Integer::encode(mpz_class const& num) {
        if (num == 0)
            return { 0 };

        size_t buffer_size = (mpz_sizeinbase(num.get_mpz_t(), 2) + 7) / 8;
        std::vector<uint8_t> buffer(buffer_size);

        size_t bytes_written = 0;
        mpz_export(
            buffer.data(),
            &bytes_written,
            1, // big-endian
            sizeof(uint8_t),
            1,
            0,
            num.get_mpz_t()
        );
        buffer.resize(bytes_written);

        if (buffer[0]  & 0x80)
            // MSB set - we have to prepend a null byte in order to comply with two's complement
            buffer.insert(buffer.begin(), 0);

        return buffer;
    }

    // Decodes a buffer holding binary data into a GMP integer and returns it
    // Input:
    // @buffer - buffer holding the integer in binary form (big-endian)
    mpz_class ASN1Integer::decode(std::vector<uint8_t> const& data) {
        mpz_class num;

        mpz_import(
            num.get_mpz_t(),
            data.size(),
            1, // big-endian
            sizeof(uint8_t),
            1,
            0,
            data.data()
        );

        return num;
    }

    ASN1BitString::ASN1BitString(std::vector<uint8_t> const& s, int unused) : ASN1Object(BIT_STRING, std::move(s)) {
        if (unused > 7)
            throw std::runtime_error("[ASN1BitString::ASN1BitString] cannot exceed 7 unused bytes");

        _value.insert(_value.begin(), static_cast<uint8_t>(unused));
        _length += 1;
    }

}