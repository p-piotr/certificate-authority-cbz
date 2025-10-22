#include "decode-key.h"


// Note: this was made to parse key generated with openssl, I doubt keys generated in some other way will work
PrivateKey parse_der_privateKey(const vector<uint8_t> &der, size_t &start){
    size_t PrivateKeyOctSize;
    try {
        PrivateKeyOctSize = decode_der_octet_string(der, start);
    } catch (const MyError &e) {
        cerr << "parse_der_privateKey: failed to decode octet string bytes " << e.what() << endl;
    }
    size_t PrivateKeyOctBegin = start;

    size_t PrivateKeySeqSize;
    try {
        PrivateKeySeqSize = decode_der_sequence(der, start);
    } catch (const MyError &e) {
        cerr << "parse_der_privateKey: failed to decode sequence bytes " << e.what() << endl;
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
        throw std::runtime_error("parse_der_privateKey: extra fields in private key sequence");

    return PrivateKey(list[0], list[1], list[2], list[3], list[4], list[5], list[6], qInv, 0);
}

PrivateKeyInfo parse_der(const vector<uint8_t> &der){
    size_t index = 0; 
    size_t PrivateKeyInfoSize;

    try {
        PrivateKeyInfoSize = decode_der_sequence(der, index);
    } catch (const MyError &e) {
        cerr << "parse_der: failed to decode sequence bytes " << e.what() << endl;
    }
    size_t PrivateKeyInfoBegin = index;

    int version;
    try {
        version = decode_der_integer(der, index).get_si();
    } catch (const MyError &e) {
        cerr << "parse_der: failed to decode version " << e.what() << endl;
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
            throw std::runtime_error("Unable to correctly interpret file: " + path + "\nFile must be in PKCS#8 format");
        }
        if(infile_buffer[i] !=  header[i]){
            throw std::runtime_error("Unable to correctly interpret file: " + path + "\nFile must be in PKCS#8 format");
        }
    }

    auto it = infile_buffer.end();
    int i = trailer.size() - 1;
    int count = 0;
    while(i >= 0){
        if(*it != trailer[i]){
            throw std::runtime_error("Unable to correctly interpret file: " + path + "\nFile must be in PKCS#8 format");
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

