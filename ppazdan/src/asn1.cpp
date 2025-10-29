#include <vector>
#include <stdexcept>
#include <queue>
#include <memory>
#include <iostream>
#include <gmpxx.h>
#include <cctype>
#include "asn1.h"
#include "debug.h"

// TODO: add memory zeroing to ASN1Object destructor (!!!)

// This namespace contains all functionality related to ASN1
namespace ASN1 {

    // Converts an ASN.1 tag (enum) to string
    const char* ASN1Parser::tag_to_string(ASN1Tag tag) {
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
            default:
            throw std::runtime_error("Unsupported ASN.1 Tag");
        }
    }

    void ASN1Parser::_ASN1Parser_update_children_values(
        std::shared_ptr<ASN1Object> object, 
        std::shared_ptr<std::vector<uint8_t>> buffer, 
        size_t additional_offset
    ) {
        // loop through all children and update their _value and _length fields
        for (auto &child : object->_children) {
            ASN1ObjectData length(
                object->_value.buffer(),
                child->_length.value_offset() + additional_offset,
                child->_length.value_size()
            );
            ASN1ObjectData value(
                object->_value.buffer(),
                child->_value.value_offset() + additional_offset,
                child->_value.value_size()
            );
            child->_length = length;
            child->_value = value;
            // then, recursively update child's children
            _ASN1Parser_update_children_values(child, buffer, additional_offset);
        }
    }

    std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode(std::shared_ptr<ASN1Object> object) {
        if (object->value().value_size() == 0) {
            throw std::runtime_error("Cannot encode ASN.1 object without value");
        }

        std::vector<uint8_t> encoded_object;
        // append tag
        encoded_object.push_back(static_cast<uint8_t>(object->tag()));
        // append length
        encoded_object.insert(
            encoded_object.end(),
            object->length().buffer()->cbegin(),
            object->length().buffer()->cend()
        );
        // append value
        encoded_object.insert(
            encoded_object.end(),
            object->value().buffer()->cbegin(),
            object->value().buffer()->cend()
        );

        // update object's internal state (_value and _length) to reflect the new buffer
        size_t length_offset = 1, length_size = object->length().value_size();
        size_t value_offset = length_offset + length_size, value_size = object->value().value_size();
        ASN1ObjectData value(std::move(encoded_object), value_offset, value_size);
        ASN1ObjectData length(value.buffer(), length_offset, length_size);
        object->_value = value;
        object->_length = length;

        return value.buffer();
    }

    std::shared_ptr<std::vector<uint8_t>> ASN1Parser::encode_all(std::shared_ptr<ASN1Object> root_object) {
        bool has_children = !root_object->children().empty();
        bool has_value = root_object->value().value_size() > 0;
        if (!(has_children ^ has_value)) {
            // the object must have either children or value, not both or none
            throw std::runtime_error("ASN.1 Object must have either children or value");
        }
        if (has_value) {
            // if the object has a value, encode it directly
            return encode(root_object);
        }
        // the object has children - encode them first
        std::vector<std::shared_ptr<std::vector<uint8_t>>> encoded_children;
        for (std::shared_ptr<ASN1Object> child : root_object->children()) {
            encoded_children.push_back(encode_all(child));
        }

        // concatenate root object tag, length and encoded children
        std::vector<uint8_t> encoded_root_object;
        encoded_root_object.push_back(static_cast<uint8_t>(root_object->tag()));
        // calculate total size of children
        size_t total_children_size = 0;
        for (auto child_data : encoded_children) {
            total_children_size += child_data->size();
        }
        // since the object has children, we need to encode the length field accordingly
        ASN1ObjectData length_field = ASN1ObjectData::calculate_length_field(total_children_size);
        // append length field
        encoded_root_object.insert(
            encoded_root_object.end(),
            length_field.buffer()->cbegin(),
            length_field.buffer()->cend()
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
        // update root object's internal state (_value and _length) to reflect the new buffer
        size_t length_offset = 1, length_size = length_field.value_size();
        size_t value_offset = length_offset + length_size, value_size = total_children_size;
        ASN1ObjectData value(std::move(encoded_root_object), value_offset, value_size);
        ASN1ObjectData length(value.buffer(), length_offset, length_size);
        root_object->_value = value;
        root_object->_length = length;

        // update children in the same way
        _ASN1Parser_update_children_values(root_object, root_object->value().buffer(), value_offset);
        return root_object->value().buffer();
    }

    // This function parses ASN.1 binary data and returns a parsed element (does not parse recursively - see ASN1Parser::decode_all)
    // Input:
    // @data - byte vector containing ASN.1 binary data
    // @offset - offset from the beginning of @data from which parsing should be started
    std::shared_ptr<ASN1Object> ASN1Parser::decode(std::shared_ptr<std::vector<uint8_t>> data, size_t offset) {
        size_t offset_t = offset;

        if (offset_t >= data->size()) {
            throw std::runtime_error("Offset out of bounds");
        }

        ASN1Tag tag = static_cast<ASN1Tag>((*data)[offset_t++]);
        if (offset_t >= data->size()) {
            throw std::runtime_error("Incomplete ASN.1 data");
        }

        size_t length = (*data)[offset_t++], tag_length_size = 2;
        if (length & 0x80) { // Long form
            size_t num_bytes = length & 0x7F;
            if (num_bytes == 0 || num_bytes > sizeof(size_t) || offset_t + num_bytes > data->size()) {
                throw std::runtime_error("Invalid length encoding");
            }
            tag_length_size += num_bytes;
            length = 0;
            for (size_t i = 0; i < num_bytes; ++i) {
                length = (length << 8) | (*data)[offset_t++];
            }
        }

        if (offset_t + length > data->size()) {
            throw std::runtime_error("Incomplete ASN.1 data");
        }

        offset += length;
        ASN1ObjectData object_data(data, offset_t, length);

        std::shared_ptr<ASN1Object> obj = std::make_shared<ASN1Object>(tag, object_data);
        return obj;
    }

    // Parses ASN.1 binary data recursively to create a module tree, returning the root element
    // See asn1.h for details
    // Input:
    // @data - byte vector containing ASN.1 binary data
    // @offset - offset in @data to start from
    std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::vector<uint8_t> &&data, size_t offset) {
        ASN1ObjectData root_data(std::move(data), 0, data.size());
        return decode_all(root_data.buffer(), offset);
    }

    // Parses ASN.1 binary data recursively to create a module tree, returning the root element
    // See asn1.h for details
    // Input:
    // @data - shared pointer to byte vector containing ASN.1 binary data
    // @offset - offset in @data to start from
    std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::shared_ptr<std::vector<uint8_t>> data, size_t offset) {
        std::shared_ptr<ASN1Object> root = decode(data, offset);
        std::queue<std::shared_ptr<ASN1Object>> to_process;
        to_process.push(root);
        while (!to_process.empty()) {
            std::shared_ptr<ASN1Object> object_to_process = to_process.front();
            to_process.pop();
            size_t object_size = object_to_process->value().value_size(), offset = 0;
            while (offset < object_size) {
                size_t cur_offset = offset + object_to_process->value().value_offset();
                std::shared_ptr<ASN1Object> object = decode(object_to_process->value().buffer(), cur_offset);
                object_to_process->_children.push_back(object);
                offset += object->total_size();
                if (object->_tag & 0x20) { // field is constructed - it contains "children" to process, too
                    to_process.push(object);
                }
            }
        }
        return root;
    }

    // Converts an ASN.1 tag (enum) to string
    void ASN1Object::print(int indent) {
        std::string output = "";
        for (int i = 0; i < indent; i++) {
            output += '\t';
        }
        output += "TYPE: ";
        output += ASN1Parser::tag_to_string(_tag);
        // output value in format depending on the tag
        std::cout << output << std::endl;
        for (std::shared_ptr<ASN1Object> child : _children) {
            child->print(indent+1);        
        }
    }

    ASN1ObjectData ASN1ObjectData::calculate_length_field(size_t length) {
        if (length < 128) {
            // short form
            std::vector<uint8_t> length_field = { static_cast<uint8_t>(length) };
            return ASN1ObjectData(std::move(length_field), 0, 1);
        }
        // long form
        std::vector<uint8_t> length_field;
        size_t length_t = length, num_bytes = 0;
        while (length_t > 0) {
            num_bytes++;
            length_t >>= 8;
        }
        length_field.push_back(static_cast<uint8_t>(0x80 | num_bytes));
        for (size_t i = num_bytes; i > 0; i--) {
            length_field.push_back(static_cast<uint8_t>((length >> ((i - 1) * 8)) & 0xFF));
        }
        return ASN1ObjectData(std::move(length_field), 0, length_field.size());
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
        for (it; it != --remainders.rend(); it++) {
            result.push_back(*it | 0x80);
        }
        result.push_back(*it);
        return result;
    }

    // Helper for ASN1ObjectIdentifier::decode - decodes a single OBJECT IDENTIFIER integer, returning a GMP integer
    // Input:
    // @rb - constant reverse iterator pointing at the last element of the encoded integer's vector
    // @re - constant reverse iterator pointing at the element before the first one of the encoded integer's vector
    mpz_class _ASN1ObjectIdentifier_decode_single_integer(std::vector<uint8_t>::const_reverse_iterator rb, std::vector<uint8_t>::const_reverse_iterator re) {
        mpz_class result = 0, multiplier = 1;
        for (auto it = rb; it != re; it++) {
            result += (*it & 0x7F) * multiplier;
            multiplier *= 128;
        }

        return result;
    }

    // The ASN.1 OBJECT IDENTIFIER encoder - returns a binary representation of OBJECT IDENTIFIER (as a buffer)
    // Input:
    // @obj_id_str - OBJECT IDENTIFIER as a string (eg. "1.23.4567.89.0")
    std::vector<uint8_t> ASN1ObjectIdentifier::encode(std::string const &obj_id_str) {
        std::vector<mpz_class> integers; // holds the parsed integers from obj_id_str, eg. "1.23.4567.89.0" -> [1, 23, 4567, 89, 0]
        std::vector<uint8_t> result;
        std::string temp = ""; // temporary string holding digits of the current integer being parsed

        for (char ch : obj_id_str) {
            // parse the string into integers
            if (ch == '.') {
                if (temp.size() == 0) { // two dots in a row or dot at the beginning
                    throw std::runtime_error("Invalid format of ASN.1 Object Identifier");
                }
                // convert the parsed integer string to GMP integer and store it
                integers.push_back(mpz_class(temp));
                temp = "";
            }
            else if (std::isdigit(ch)) {
                temp += ch;
            }
            else { // illegal character
                throw std::runtime_error("Invalid character in ASN.1 Object Identifier");
            }
        }
        if (temp.size() > 0) { // append the last integer, since it won't be followed by a dot
            integers.push_back(mpz_class(temp));
        }

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
    std::string ASN1ObjectIdentifier::decode(ASN1ObjectData data) {
        std::string integer_str, result = "";
        auto value_reverse_start = data.buffer()->crbegin() + (data.buffer()->size() - 
            data.value_offset() - data.value_size());
        auto value_reverse_end = value_reverse_start + data.value_size();
        auto rb = value_reverse_start, re = rb + 1;

        // parse (from the end to the beginning), till the first two integers
        while (re != value_reverse_end) {
            if (*re & 0x80) { // MSB set - continue
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
        mpz_class x, y;
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
        std::string x_str = x.get_str(), y_str = y.get_str();
        result.insert(result.cbegin(), y_str.begin(), y_str.end());
        result.insert(result.cbegin(), '.');
        result.insert(result.cbegin(), x_str.begin(), x_str.end());

        return result;
    }

    // Encodes a GMP integer to the binary form, big-endian (ANS.1 compatibile), returning a buffer
    // Input:
    // @num - GMP integer to encode
    std::vector<uint8_t> ASN1Integer::encode(mpz_class const &num) {
        if (num == 0) {
            return { 0 };
        }

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

        if (buffer[0] & 0x80) {
            // MSB set - we have to prepend a null byte in order to comply with two's complement
            buffer.insert(buffer.begin(), 0);
        }

        return buffer;
    }

    // Decodes a buffer holding binary data into a GMP integer and returns it
    // Input:
    // @buffer - buffer holding the integer in binary form (big-endian)
    mpz_class ASN1Integer::decode(ASN1ObjectData data) {
        mpz_class num;

        mpz_import(
            num.get_mpz_t(),
            data.value_size(),
            1, // big-endian
            sizeof(uint8_t),
            1,
            0,
            data.buffer()->data() + data.value_offset()
        );

        return num;
    }

}