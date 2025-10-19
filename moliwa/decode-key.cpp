#include "reusable.h"
#include <gmpxx.h>
#include <fstream>
#include <iostream>
#include "encoding.h"

using std::ifstream;
using std::cout;
using std::endl;

class PrivateKey {
    int version;
    mpz_class n, e, d, p, q, dP, dQ, qInv;
public:
    PrivateKey() : version(0), n(0), e(0), d(0), p(0), q(0), dP(0), dQ(0), qInv(0) {}
    PrivateKey (
    mpz_class &n_,
    mpz_class &e_,
    mpz_class &d_,
    mpz_class &p_,
    mpz_class &q_,
    mpz_class &dP_,
    mpz_class &dQ_,
    mpz_class &qInv_,
    size_t version_ = 0
    ) : version(version_), n(n_), e(e_), d(d_), p(p_), q(q_), dP(dP_), dQ(dQ_), qInv(qInv_) {}



    vector<uint8_t> encode() const {
            return encode_der_sequence({
                encode_der_integer(version),
                encode_der_integer(n),
                encode_der_integer(e),
                encode_der_integer(d),
                encode_der_integer(p),
                encode_der_integer(q),
                encode_der_integer(dP),
                    encode_der_integer(dQ),
                encode_der_integer(qInv),
            });
    }
};

class PrivateKeyInfo {
    size_t version;
    AlgorithmIdentifier privateKeyAlgorithm;
    PrivateKey privateKey;
public:
    PrivateKeyInfo() {}
    PrivateKeyInfo(const AlgorithmIdentifier &privateKeyAlgorithm_, const PrivateKey &privateKey_, int version_ = 0) : version(version_), privateKeyAlgorithm(privateKeyAlgorithm_), privateKey(privateKey_) {}

    PrivateKeyInfo (
    mpz_class &n_,
    mpz_class &e_,
    mpz_class &d_,
    mpz_class &p_,
    mpz_class &q_,
    mpz_class &dP_,
    mpz_class &dQ_,
    mpz_class &qInv_,
    size_t version_ = 0
    ) : privateKeyAlgorithm("1.2.840.113549.1.1.1"), privateKey(n_, e_, d_, p_, q_, dP_, dQ_, qInv_, 0), version(version_) {}

};

// Note: this was made to parse key generated with openssl, I doubt keys generated in some other way will work
PrivateKey parse_der_privateKey(const vector<uint8_t> &der, size_t &start){
    if(der[start++] != 0x04)
        throw std::runtime_error("PrivateKeyInfo::parse_der_privateKey: Der encoding not matching PrivateKeyInfo ASN1 structure (PrivateKey first byte does not indicate OCTET STRING)");
    size_t oct_length = decode_der_length(der, start);
    size_t begin = start;

    if(der[start++] != 0x30)
        throw std::runtime_error("PrivateKeyInfo::parse_der_privateKey: Der encoding not matching PrivateKeyInfo ASN1 structure (PrivateKey first member of OCTET STRING, lacks bytes indicating SEQUENCE)");

    size_t seq_length = decode_der_length(der, start);


    //Version must always be set to 0
    //So we are just handling this case
    if(der[start++] != 0x02)
        throw std::runtime_error("parse_der_privateKey: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );
    if(der[start++] != 0x01)
        throw std::runtime_error("parse_der_privateKey: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );
    if(der[start++] != 0x00)
        throw std::runtime_error("parse_der_privateKey: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );

    if(der_check_finish(der, start))
        throw std::runtime_error("PrivateKeyInfo::parse_der_privateKey: lacking some fields in private key sequence");

    vector<mpz_class> list(7);
    for(int i = 0; i < 7; i++){
        list[i] = decode_der_integer(der, start);
        der_check_boundry(seq_length, begin, start);
        der_check_boundry(oct_length, begin, start);
        if(der_check_finish(der, start))
            throw std::runtime_error("parse_der_privateKey: lacking some fields in private key sequence");
    }

    mpz_class qInv = decode_der_integer(der, start);
    der_check_boundry(seq_length, begin, start);
    der_check_boundry(oct_length, begin, start);
    if(!der_check_finish(der, start))
        throw std::runtime_error("parse_der_privateKey: extra fields in private key sequence");

    return PrivateKey(list[0], list[1], list[2], list[3], list[4], list[5], list[6], qInv, 0);
}

PrivateKeyInfo parse_der(const vector<uint8_t> &der){
    size_t index = 0; 

    // First byte must be 0x30 to indicate SEQUENCE
    if(der[index++] != 0x30){
        throw std::runtime_error("PrivateKeyInfo::parse_der: Der encoding not matching PrivateKeyInfo ASN1 structure (First byte does not indicate SEQUENCE)" );
    }

    size_t PrivateKeyInfoSize = decode_der_length(der, index);
    size_t begin = index;

    //Version must always be set to 0
    //So we are just handling this case
    if(der[index++] != 0x02)
        throw std::runtime_error("PrivateKeyInfo::parse_der: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );
    if(der[index++] != 0x01)
        throw std::runtime_error("PrivateKeyInfo::parse_der: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );
    if(der[index++] != 0x00)
        throw std::runtime_error("PrivateKeyInfo::parse_der: Der encoding not matching PrivateKeyInfo ASN1 structure (Version bytes are wrong)" );

    AlgorithmIdentifier privateKeyAlgorithm = parse_der_algorithmIdentifier(der, index);
    der_check_boundry(PrivateKeyInfoSize, begin, index);

    PrivateKey privateKey = parse_der_privateKey(der, index);
    der_check_boundry(PrivateKeyInfoSize, begin, index);
    if(!der_check_finish(der, index))
        throw std::runtime_error("PrivateKeyInfo::parse_der_privateKey: extra fields in private key sequence");
    return PrivateKeyInfo(privateKeyAlgorithm, privateKey, 0);
}

// I orginially inteded this function, and all the other functions connected to parsing the file to be part of the PrivateKeyInfo class
// However I realized that it would require that PrivateKeyInfo class to be first initialized as empty
// It would thus need to copy the members of the class when parsing it, which I don't like as it diminishes perfomence a bit
PrivateKeyInfo read_from_file(const string &path){
    string header = "-----BEGIN PRIVATE KEY-----";
    string trailer = "-----END PRIVATE KEY-----\n";

    ifstream infile(path, std::ios::binary | std::ios::ate);
    if (!infile) {
        throw std::runtime_error("Unable to open file: " + path);
    }

    std::streamsize size = infile.tellg();
    if (size < 0) {
        throw std::runtime_error("tellg() failed to determine file size of " + path);
    }

    vector<uint8_t> infile_buffer(size-1);
    infile.seekg(0, std::ios::beg);
    if (!infile.read(reinterpret_cast<char*>(infile_buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + path);
    }
    infile.close();


    for(int i = 0; i < header.size(); i++) {
        if (i >= infile_buffer.size()){
            throw std::runtime_error("Unable to correctly interpret file: " + path);
        }
        if(infile_buffer[i] !=  header[i]){
            throw std::runtime_error("Unable to correctly interpret file: " + path);
        }
    }

    auto it = infile_buffer.end();
    int i = trailer.size() - 1;
    int count = 0;
    while(i >= 0){
        if(*it != trailer[i]){
            throw std::runtime_error("Unable to correctly interpret file: " + path);
        }
        count++;
        i--;
        it--;
    }

    string base64(infile_buffer.begin() + header.size() + 1, infile_buffer.end() - count);
    size_t writeIndex = 0;
    for (size_t i = 0; i < base64.size(); i++){
        if(base64[i] == '\n')
            continue;
        base64[writeIndex++] = base64[i];
    }
    base64.resize(writeIndex);
    vector<uint8_t > decoded = base64_decode(base64);
    return parse_der(decoded);
}

int main(){
    PrivateKeyInfo PrKeyInf = read_from_file("private-key.pem");

    return 0;
}
