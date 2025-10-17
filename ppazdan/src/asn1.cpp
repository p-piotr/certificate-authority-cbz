#include <vector>
#include <stdexcept>
#include <queue>
#include <memory>
#include <iostream>
#include "asn1.h"

ASN1Object::ASN1Object(uint8_t tag, size_t tag_length_size, const std::vector<uint8_t>& value) : tag(tag), tag_length_size(tag_length_size), value(value) {
    #ifdef DEBUG
    std::cerr << "ASN1Object created: tag=" << std::hex << (int)tag << ", tag_length_size=" << std::dec << tag_length_size << ", value_length=" << value.size() << std::endl;
    #endif
}

ASN1Object::~ASN1Object() {
    #ifdef DEBUG
    std::cerr << "ASN1Object destroyed: tag=" << std::hex << (int)tag << ", tag_length_size=" << std::dec << tag_length_size << ", value_length=" << value.size() << std::endl;
    #endif
}

std::shared_ptr<ASN1Object> ASN1Parser::parse(const std::vector<uint8_t>& data, size_t offset) {
    if (offset >= data.size()) {
        throw std::runtime_error("Offset out of bounds");
    }

    uint8_t tag = data[offset++];
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

    std::shared_ptr<ASN1Object> obj = std::make_shared<ASN1Object>(tag, tag_length_size, value);
    return obj;
}

std::shared_ptr<ASN1Object> ASN1Parser::parseAll(const std::vector<uint8_t>& data) {
    std::shared_ptr<ASN1Object> root = parse(data, 0);
    std::queue<std::shared_ptr<ASN1Object>> to_process;
    to_process.push(root);
    while (!to_process.empty()) {
        std::shared_ptr<ASN1Object> object_to_process = to_process.front();
        to_process.pop();
        size_t object_size = object_to_process->value.size(), offset = 0;
        while (offset < object_size) {
            std::shared_ptr<ASN1Object> object = parse(object_to_process->value, offset);
            object_to_process->children.push_back(object);
            offset += object->total_length();
            if (object->tag & 0x20) { // field is constructed - it contains "children" to process, too
                to_process.push(object);
            }
        }
    }
    return root;
}