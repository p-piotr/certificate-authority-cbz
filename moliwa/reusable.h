#ifndef reusable
#define reusable

#include "encoding.h"
#include "decoding.h"
#include <iostream>

using std::endl;


//  According to RFC
//  PKCS1Algorithms    ALGORITHM-IDENTIFIER ::= {
//  { OID rsaEncryption              PARAMETERS NULL } |
//  { OID md2WithRSAEncryption       PARAMETERS NULL } |
//  { OID md5WithRSAEncryption       PARAMETERS NULL } |
//  { OID sha1WithRSAEncryption      PARAMETERS NULL } |
//  { OID sha256WithRSAEncryption    PARAMETERS NULL } |
//  { OID sha384WithRSAEncryption    PARAMETERS NULL } |
//  { OID sha512WithRSAEncryption    PARAMETERS NULL } |
//  { OID id-RSAES-OAEP PARAMETERS RSAES-OAEP-params } |
//  PKCS1PSourceAlgorithms                             |
//  { OID id-RSASSA-PSS PARAMETERS RSASSA-PSS-params } , ...  -- Allows for future expansion --
// }
//
//  Note: as of now only rsaEncryption is handled

struct AlgorithmIdentifier {
    string algorithm; // OID
    vector<uint8_t> parameters;
    string attr;


    AlgorithmIdentifier(string algorithm_, vector<uint8_t> parameters_ = der_null) : algorithm(algorithm_), parameters(parameters_) {
        try{
            attr = OIDsToAttributes.at(algorithm);
        } catch (const std::out_of_range& e){
            throw MyError("AlgorithmIdentifier constructor: received OID value that is not handled");
        }

        if(algorithm == "1.2.840.113549.1.1.1" || algorithm == "1.2.840.113549.1.1.11" || algorithm == "2.16.840.1.101.3.4.2.1")
            parameters = der_null;
        // If different algorithms to be handled parse parameters here
    }

    vector<uint8_t> encode() const {
        return encode_der_sequence({
            encode_der_oid(algorithm),
            parameters
        });
    }
};

struct PublicKey{
    mpz_class n;
    mpz_class e;
    PublicKey(const mpz_class &modulus_, const mpz_class &exponent_) : n(modulus_), e(exponent_) {}
    vector<uint8_t> encode() const {
        vector<uint8_t> sequence = encode_der_sequence({encode_der_integer(n), encode_der_integer(e)});
        return encode_der_bitstring(sequence);
    }
};

void print_bytes(const vector<uint8_t> &bytes);
void print_bytes_commas(const vector<uint8_t> &bytes);
void der_check_boundry(size_t length, size_t start, size_t curr);
AlgorithmIdentifier parse_der_algorithmIdentifier(const vector<uint8_t> &der, size_t &start);
bool der_check_finish(const vector<uint8_t> &der, const size_t &curr);

template <typename T>
inline void zeroize(vector<T> &vec){
    std::fill(vec.begin(), vec.end(), 0);
}
inline void zeroize(string &str){
    std::fill(str.begin(), str.end(), 0);
}

enum string_t{
    IA5STRING,
    PRINTABLE_STRING,
    UTF8_STRING
};

inline const vector<uint8_t> der_null = {0x05, 0x00};
static const map<string, string_t> AttributeStringTypes = {

    {"2.5.4.6",                PRINTABLE_STRING},   // countryName
    {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
    {"2.5.4.7",                UTF8_STRING},        // localityName
    {"2.5.4.10",               UTF8_STRING},        // organizationName
    {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
    {"2.5.4.3",                UTF8_STRING},        // commonName
    {"1.2.840.113549.1.9.1",   IA5STRING},          // emailAddress
    {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
    {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
};


#endif
