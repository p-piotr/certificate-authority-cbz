#include "mappings.h"
#include "decode-key.h"
#include "encoding.h"
#include "csrclass.h"
#include "input_and_output.h"



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


    #define SKIP_INPUT

    // For debugging not to enter the the input manually each time
    #ifdef SKIP_INPUT
    vector<pair<string,string>> subject = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    vector<pair<string,string>> attrs = {};
    #endif

    // If not skipping input just call the functions responsible for getting input from the user
    #ifndef SKIP_INPUT
    vector<pair<string,string>> subject = ask_for_subject_info();
    cout << endl;
    vector<pair<string,string>> attrs = ask_for_attrs_info();
    cout << endl;
    #endif

    // this buffer will hold the raw DER-encoded bytes of PrivateKey
    // it will be readin from the file and used to create PrivateKeyInfo object
    // and then it will be zeroized immiediately after
    vector<uint8_t> file_buffer; 
    read_privatekey_from_file(inputFile, file_buffer); 
    print_bytes(file_buffer);
    //PrivateKey PKey = privateKeyInfo.getPrivateKeyReference();

    //CertificationRequest CR(
    //    subject,
    //    PKey.n,
    //    PKey.e,
    //    attrs
    //);
    //
    //vector<uint8_t> bytes = CR.encode(PKey);
    //string out = base64_encode(bytes);
    //write_csr_to_file(out, outputFile);

    //// ---- TEST SIGNATURE VERIFICATION ----
    //PublicKey pub_key = CR.getPublicKeyReference();
    //vector<uint8_t> mess = CR.getCRIBytes();
    //vector<uint8_t> signature = CR.getSignatureReference();
    //cout << std::boolalpha << RSASSA_PKCS1_V1_5_VERIFY(pub_key, mess, signature) << endl;


    return 0;
}
