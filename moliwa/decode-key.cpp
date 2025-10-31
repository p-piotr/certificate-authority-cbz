#include "decode-key.h"


// Note: this was made to parse key generated with openssl, I doubt keys generated in some other way will work
PrivateKey parse_der_privateKey(const vector<uint8_t> &der, size_t &start){
    size_t PrivateKeyOctSize;
    try {
        PrivateKeyOctSize = decode_der_octet_string(der, start);
    } catch (const MyError &e) {
        cerr << "parse_der_privateKey: failed to decode octet string bytes " << e.what() << endl;
        exit(42);
    }
    size_t PrivateKeyOctBegin = start;

    size_t PrivateKeySeqSize;
    try {
        PrivateKeySeqSize = decode_der_sequence(der, start);
    } catch (const MyError &e) {
        cerr << "parse_der_privateKey: failed to decode sequence bytes " << e.what() << endl;
        exit(42);
    }
    size_t PrivateKeySeqBegin = start;


    //Version must always be set to 0
    int version = decode_der_integer(der, start).get_si();
    if(version != 0)
        throw MyError("parse_der_privateKey: version is not zero" );

    if(der_check_finish(der, start))
        throw MyError("parse_der_privateKey: lacking some fields in private key sequence");

    vector<mpz_class> list(7);
    for(int i = 0; i < 7; i++){
        list[i] = decode_der_integer(der, start);
        der_check_boundry(PrivateKeySeqSize, PrivateKeySeqBegin, start);
        der_check_boundry(PrivateKeyOctSize, PrivateKeyOctBegin, start);
        if(der_check_finish(der, start))
            throw MyError("parse_der_privateKey: lacking some fields in private key sequence");
    }

    mpz_class qInv = decode_der_integer(der, start);
    der_check_boundry(PrivateKeySeqSize, PrivateKeySeqBegin, start);
    der_check_boundry(PrivateKeyOctSize, PrivateKeyOctBegin, start);
    if(!der_check_finish(der, start))
        throw MyError("parse_der_privateKey: extra fields in private key sequence");

    return PrivateKey(list[0], list[1], list[2], list[3], list[4], list[5], list[6], qInv, 0);
}

PrivateKeyInfo parse_der(const vector<uint8_t> &der){
    size_t index = 0; 
    size_t PrivateKeyInfoSize;

    try {
        PrivateKeyInfoSize = decode_der_sequence(der, index);
    } catch (const MyError &e) {
        cerr << "parse_der: failed to decode sequence bytes " << e.what() << endl;
        exit(42);
    }
    size_t PrivateKeyInfoBegin = index;

    int version;
    try {
        version = decode_der_integer(der, index).get_si();
    } catch (const MyError &e) {
        cerr << "parse_der: failed to decode version " << e.what() << endl;
        exit(42);
    }

    //Version must always be set to 0
    if(version != 0)
        throw MyError("parse_der: version is not zero");

    AlgorithmIdentifier privateKeyAlgorithm = parse_der_algorithmIdentifier(der, index);
    der_check_boundry(PrivateKeyInfoSize, PrivateKeyInfoBegin, index);

    PrivateKey privateKey = parse_der_privateKey(der, index);
    der_check_boundry(PrivateKeyInfoSize, PrivateKeyInfoBegin, index);
    if(!der_check_finish(der, index))
        throw std::runtime_error("parse_der_privateKey: extra fields in private key sequence");
    return PrivateKeyInfo(privateKeyAlgorithm, privateKey, 0);
}


