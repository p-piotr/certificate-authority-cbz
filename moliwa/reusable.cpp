#include "encoding.h"
#include "reusable.h"

void print_bytes(const vector<uint8_t> &bytes){
    for(uint8_t byte : bytes)
        printf("0x%.2X, ", byte);
    printf("\n");
}

void print_bytes_commas(const vector<uint8_t> &bytes){
    for(uint8_t byte : bytes)
        printf("%.2X ", byte);
    printf("\n");
}

AlgorithmIdentifier parse_der_algorithmIdentifier(const vector<uint8_t> &der, size_t &start){
    size_t AlgorithmIdentifierSize;
    try {
        AlgorithmIdentifierSize = decode_der_sequence(der, start);
    } catch (const MyError &e) {
        std::cerr << "parse_der_algorithmIdentifier: failed to decode sequence bytes " << e.what() << endl;
        std::exit(1);
    }
    size_t AlgorithmIdentifierBegin = start;

    string oid = decode_der_oid(der, start);
    vector<uint8_t> parameters;
    while(start < AlgorithmIdentifierBegin + AlgorithmIdentifierSize){
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
