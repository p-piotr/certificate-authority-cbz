#include "encoding.h"
#include "input_and_output.h"
#include "sign.h"
#include "PKCSObjects.h"

// this function was just added to test functionality it's not really needed yet
void test_signature_verification(PKCS::CertificationRequest &CR){
    cout  << endl << "testing signature verification" << endl;

    // get public key from certification certification request
    const PKCS::RSAPublicKey &pub_key = CR.getPublicKeyReference();
    // get certifcationRequestInfo encoded as DER (that's the part of CSR that is actually signed)
    const vector<uint8_t> &mess = CR.getCertificationRequestInfoReference().encode();
    // get signature
    const vector<uint8_t> &signature = CR.getSignatureReference();
    // verify signature
    cout << std::boolalpha << RSASSA_PKCS1_V1_5_VERIFY(pub_key, mess, signature) << endl;
}



int main(int argc, char* argv[]){
    // file to read Private Key from
    string inputFile;
    // file to write into 
    string outputFile;

    handle_arguments(argc, argv, inputFile, outputFile);

    // Can be used for debugging in order not to input data each time the program is run
    #ifdef SKIP_INPUT
    vector<pair<string,string>> subject_info = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    vector<pair<string,string>> attributes = {{"1.2.840.113549.1.9.2", "example@agh.edu.pl"}};
    #else
    // If not skipping input just call the functions responsible for getting input from the user
    vector<pair<string,string>> subject_info = ask_for_subject_info();
    vector<pair<string,string>> attributes = ask_for_attrs_info();
    #endif

    // make the mpz_class to zeroize the memory when deallocating
    mpz_set_zeroize_policy();

    // this buffer will hold the raw DER-encoded bytes of PrivateKey
    // it will be read in from the file and used to create PrivateKeyInfo object
    // and then it will be zeroized immiediately after
    vector<uint8_t> file_buffer; 
    // start decoding from first byte
    size_t offset = 0;
    read_privatekey_from_file(inputFile, file_buffer); 

    PKCS::PrivateKeyInfo private_key;
    // decode the key from file
    try{
        private_key = PKCS::PrivateKeyInfo::decode(file_buffer,offset);
    } catch (const MyError &e) {
        std::cerr << "failed to decode file with private key" << endl;
        print_nested(e, 0);
        exit(1);
    }
    // file buffer is not longer needed so it can be zeroized
    zeroize(file_buffer);

    // extract public key from private key
    const mpz_class &e = private_key.getPrivateKeyReference().getEReference();
    const mpz_class &n = private_key.getPrivateKeyReference().getNReference();

    // create certifcation request object using extracted public key and input from the user
    PKCS::CertificationRequest certification_request(
        std::move(subject_info),
        rsaEncryption, 
        std::move(n), 
        std::move(e),
        std::move(attributes),
        sha256WithRSAEncryption
    );

    // generate signature for the CSR
    certification_request.sign(private_key);

    // encode the CSR int DER
    vector<uint8_t> DER_encoding = certification_request.encode();
    // enocde DER encoding of CSR into base64
    string base64_output = base64_encode(DER_encoding);
    // write base64 and DER encoded CSR into the file
    write_csr_to_file(base64_output, outputFile);

    // those are no longer need they can be zeroized
    zeroize(DER_encoding);
    zeroize(base64_output);

    test_signature_verification(certification_request);
    
    return 0;
}
