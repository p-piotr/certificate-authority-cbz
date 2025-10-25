#include <vector>
#include <stdexcept>
#include <queue>
#include <memory>
#include <iostream>
#include <gmpxx.h>
#include <cctype>
#include "asn1.h"
#include "debug.h"

// This namespace contains all functionality related to ASN1
namespace ASN1 {

    // Creates an ASN1Object, initializes its fields and optionally prints a debug message
    ASN1Object::ASN1Object(ASN1Tag tag, size_t tag_length_size, std::vector<uint8_t>const &&value) : _tag(tag), _tag_length_size(tag_length_size), _value(value) {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object created: tag=" << std::hex << (int)tag << ", tag_length_size=" << std::dec << tag_length_size << ", value_length=" << value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

    // Destroys an ASN1Object and optionally prints a debug message
    ASN1Object::~ASN1Object() {
        #ifdef ASN1_DEBUG
        std::cerr << "[ASN1Object] ASN1Object destroyed: tag=" << std::hex << (int)_tag << ", tag_length_size=" << std::dec << _tag_length_size << ", value_length=" << _value.size() << std::endl;
        #endif // ASN1_DEBUG
    }

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

    std::shared_ptr<ASN1Object> ASN1Parser::decode(std::vector<uint8_t> const &data, size_t offset) {
        if (offset >= data.size()) {
            throw std::runtime_error("Offset out of bounds");
        }

        ASN1Tag tag = static_cast<ASN1Tag>(data[offset++]);
        if (offset >= data.size()) {
            throw std::runtime_error("Incomplete ASN.1 data");
        }

        size_t length = data[offset++], tag_length_size = 2;
        if (length & 0x80) { // Long form
            size_t num_bytes = length & 0x7F;
            if (num_bytes == 0 || num_bytes > sizeof(size_t) || offset + num_bytes > data.size()) {
                throw std::runtime_error("Invalid length encoding");
            }
            tag_length_size += num_bytes;
            length = 0;
            for (size_t i = 0; i < num_bytes; ++i) {
                length = (length << 8) | data[offset++];
            }
        }

        if (offset + length > data.size()) {
            throw std::runtime_error("Incomplete ASN.1 data");
        }

        std::vector<uint8_t> value(data.begin() + offset, data.begin() + offset + length);
        offset += length;

        std::shared_ptr<ASN1Object> obj = std::make_shared<ASN1Object>(tag, tag_length_size, std::move(value));
        return obj;
    }

    std::shared_ptr<ASN1Object> ASN1Parser::decode_all(std::vector<uint8_t> const &data, size_t offset) {
        std::shared_ptr<ASN1Object> root = decode(data, offset);
        std::queue<std::shared_ptr<ASN1Object>> to_process;
        to_process.push(root);
        while (!to_process.empty()) {
            std::shared_ptr<ASN1Object> object_to_process = to_process.front();
            to_process.pop();
            size_t object_size = object_to_process->_value.size(), offset = 0;
            while (offset < object_size) {
                std::shared_ptr<ASN1Object> object = decode(object_to_process->_value, offset);
                object_to_process->_children.push_back(object);
                offset += object->total_size();
                if (object->_tag & 0x20) { // field is constructed - it contains "children" to process, too
                    to_process.push(object);
                }
            }
        }
        return root;
    }

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
    // into an GMP integer
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

    std::vector<uint8_t> ASN1ObjectIdentifier::encode(std::string const &obj_id_str) {
        std::vector<mpz_class> integers;
        std::vector<uint8_t> result;
        std::string temp = "";

        for (char ch : obj_id_str) {
            if (ch == '.') {
                if (temp.size() == 0) {
                    throw std::runtime_error("Invalid format of ASN.1 Object Identifier");
                }
                integers.push_back(mpz_class(temp));
                temp = "";
            }
            else if (std::isdigit(ch)) {
                temp += ch;
            }
            else {
                throw std::runtime_error("Invalid character in ASN.1 Object Identifier");
            }
        }
        if (temp.size() > 0) {
            integers.push_back(mpz_class(temp));
        }

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

    std::string ASN1ObjectIdentifier::decode(std::vector<uint8_t> const &obj_id) {
        std::string integer_str, result = "";
        auto rb = obj_id.rbegin(), re = rb + 1;

        while (re != obj_id.rend()) {
            if (*re & 0x80) {
                re++;
                continue;
            }
            integer_str = _ASN1ObjectIdentifier_decode_single_integer(rb, re).get_str();
            result.insert(result.cbegin(), integer_str.begin(), integer_str.end());
            result.insert(result.cbegin(), '.');
            rb = re;
            re = rb + 1;
        }

        mpz_class double_integer = _ASN1ObjectIdentifier_decode_single_integer(rb, re);
        mpz_class x, y;
        if (double_integer < 40) {
            x = 0;
            y = double_integer;
        }
        else if (double_integer < 80) {
            x = 1;
            y = double_integer - 40;
        }
        else {
            x = 2;
            y = double_integer - 80;
        }
        std::string x_str = x.get_str(), y_str = y.get_str();
        result.insert(result.cbegin(), y_str.begin(), y_str.end());
        result.insert(result.cbegin(), '.');
        result.insert(result.cbegin(), x_str.begin(), x_str.end());

        return result;
    }

    std::vector<uint8_t> ASN1Integer::encode(mpz_class const &num) {
        if (num == 0) {
            return { 0 };
        }

        size_t buffer_size = mpz_sizeinbase(num.get_mpz_t(), 256);
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
        return buffer;
    }

    mpz_class ASN1Integer::decode(std::vector<uint8_t> const &buffer) {
        mpz_class num;

        mpz_import(
            num.get_mpz_t(),
            buffer.size(),
            1, // big-endian
            sizeof(uint8_t),
            1,
            0,
            buffer.data()
        );

        return num;
    }

}