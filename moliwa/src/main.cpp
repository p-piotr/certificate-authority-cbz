#include "encoding.h"
#include "input_and_output.h"
#include "sign.h"
#include "PKCSObjects.h"


int main(int argc, char* argv[]){
    // file to read Private Key from
    string inputFile;
    // file to write into 
    string outputFile;

    // handle the parameters
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        // -in flag is used to indicate inputFile
        if (arg == "-in" && i + 1 < argc) {
            inputFile = argv[++i];
        // -out flag is used to indicate outputFile
        } else if (arg == "-out" && i + 1 < argc) {
            outputFile = argv[++i];
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    // if user forgot some parameters print usage message and exit 
    if (inputFile.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
    if (outputFile.empty()) {
        print_usage(argv[0]);
        exit(1);
    }



    // For debugging not to enter the the input manually each time
    #ifdef SKIP_INPUT
    vector<pair<string,string>> subject_info = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    vector<pair<string,string>> attributes = {{"1.2.840.113549.1.9.2", "example@agh.edu.pl"}};
    #endif

    // If not skipping input just call the functions responsible for getting input from the user
    #ifndef SKIP_INPUT
    vector<pair<string,string>> subject_info = ask_for_subject_info();
    cout << endl;
    vector<pair<string,string>> attributes = ask_for_attrs_info();
    cout << endl;
    #endif


    // this buffer will hold the raw DER-encoded bytes of PrivateKey
    // it will be readin from the file and used to create PrivateKeyInfo object
    // and then it will be zeroized immiediately after
    vector<uint8_t> file_buffer; 
    size_t offset = 0;
    PKCS::PrivateKeyInfo private_key;
    read_privatekey_from_file(inputFile, file_buffer); 
    try{
        private_key = PKCS::PrivateKeyInfo::decode(file_buffer,offset);
    } catch (const MyError &e) {
        print_nested(e, 0);
        std::cerr << "failed to decode file with private key" << endl;
        exit(1);
    }
    zeroize(file_buffer);

    mpz_class e = private_key.getPrivateKeyReference().getEReference();
    mpz_class n = private_key.getPrivateKeyReference().getNReference();
    PKCS::CertificationRequest certification_request(std::move(subject_info),
                                   rsaEncryption, 
                                   std::move(n), 
                                   std::move(e),
                                   std::move(attributes),
                                   sha256WithRSAEncryption
                                   );
    certification_request.sign(private_key);

    vector<uint8_t> DER_encoding = certification_request.encode();
    string base64_output = base64_encode(DER_encoding);
    write_csr_to_file(base64_output, outputFile);
    zeroize(DER_encoding);
    zeroize(base64_output);

    // test signature verification
    cout  << endl << "testing signature verification" << endl;
    PKCS::RSAPublicKey pub_key = certification_request.getPublicKeyReference();
    vector<uint8_t> mess = certification_request.getCertificationRequestInfoReference().encode();
    vector<uint8_t> signature = certification_request.getSignatureReference();
    cout << std::boolalpha << RSASSA_PKCS1_V1_5_VERIFY(pub_key, mess, signature) << endl;


    return 0;
}
