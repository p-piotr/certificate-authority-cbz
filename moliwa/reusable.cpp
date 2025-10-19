#include "encoding.h"
#include "reusable.h"

void print_bytes(const vector<uint8_t> &bytes){
    for(uint8_t byte : bytes)
        printf("%.2X ", byte);
    printf("\n");
}

AlgorithmIdentifier parse_der_algorithmIdentifier(const vector<uint8_t> &der, size_t &start){
    if(der[start++] != 0x30){
        throw std::runtime_error("parse_der_algorithmIdentifier: Der encoding not matching AlgorithmIdentifier structure (First byte does not indicate SEQUENCE)" );
    }

    size_t seq_length = decode_der_length(der, start);
    if (start + seq_length > der.size()) {
        throw std::runtime_error("parse_der_algorithmIdentifier: length exceeds data size");
    }
    size_t begin = start;

    vector<uint32_t> oid = decode_der_oid(der, start);
    vector<uint8_t> parameters;
    while(start < begin + seq_length){
        parameters.push_back(der[start++]);
    }
    return AlgorithmIdentifier(oid, parameters);
}

void der_check_boundry(size_t length, size_t start, size_t curr) {
    if(start + length < curr)
        throw std::runtime_error("Pointer went out of bounds when parsing DER" );
}

bool der_check_finish(const vector<uint8_t> &der, const size_t &curr) {
    return (der.size() == curr);
}
