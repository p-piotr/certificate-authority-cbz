#ifndef reusable
#define reusable

#include "encoding.h"
#include <iostream>

using std::endl;



struct AlgorithmIdentifier {
    vector<uint32_t> algorithm; // OID
    vector<uint8_t> parameters;
    string attr;
    void constr(){
        string serial = serialize_oid(algorithm);
        try{
            attr = OIDsToAttributes.at(serial);
        } catch (const std::out_of_range& e){
            std::cerr << "Error: not handled algorithm of with OID \'" << serial << "\'" << endl;
        }

        if(attr == "1.2.840.113549.1.1.1" || attr == "1.2.840.113549.1.1.11")
            parameters = der_null;

        // If different algorithms to be handled parse parameters here
    }

    AlgorithmIdentifier() : algorithm(split_oid("1.2.840.113549.1.1.1")), parameters(der_null) {}

    AlgorithmIdentifier(string algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(split_oid(algorithm_)), parameters(parameters_) {
        constr();
    }

    AlgorithmIdentifier(vector<uint32_t> algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(algorithm_), parameters(parameters_)   {
        constr();
    }
    vector<uint8_t> encode() const {
        return encode_der_sequence({
            encode_der_oid(algorithm),
            parameters
        });
    }
};

void print_bytes(const vector<uint8_t> &bytes);
void der_check_boundry(size_t length, size_t start, size_t curr);
AlgorithmIdentifier parse_der_algorithmIdentifier(const vector<uint8_t> &der, size_t &start);
bool der_check_finish(const vector<uint8_t> &der, const size_t &curr);
#endif
