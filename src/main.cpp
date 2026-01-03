#include <iostream>
#include <vector>
#include <utility>
#include "utils/io.h"
#include "pkcs/sign.h"
#include "pkcs/pkcs.h"
#include "utils/security.hpp"
#include "utils/utils.hpp"
#include "utils/base64.h"
#include "pkcs/private_key.h"

// this function was just added to test functionality it's not really needed yet
void test_signature_verification(CBZ::PKCS::CertificationRequest& CR){
    using namespace CBZ::PKCS;

    std::cout << std::endl << "testing signature verification" << std::endl;

    // get public key from certification certification request
    const RSAPublicKey& pub_key = CR.get_public_key();
    // get certifcationRequestInfo encoded as DER (that's the part of CSR that is actually signed)
    const std::vector<uint8_t>& mess = CR.get_certification_request_info().encode();
    // get signature
    const std::vector<uint8_t>& signature = CR.get_signature();
    // verify signature
    std::cout << std::boolalpha << Signature::RSASSA_PKCS1_V1_5_VERIFY(pub_key, mess, signature) << std::endl;
}

// prints out how to call the program
static void print_usage(const std::string& name) {
    std::cout << "Usage: " << name << " -in <inputfile> -out <outputfile>" << std::endl << std::endl;
}

// this function is used handle the command-line arguments
void handle_arguments(
    int argc, char** argv, 
    std::string& inputFile, std::string& outputFile
) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        // -in flag is used to indicate inputFile
        if (arg == "-in" && i + 1 < argc) {
            inputFile = argv[++i];
        } 
        // -out flag is used to indicate outputFile
        else if (arg == "-out" && i + 1 < argc) {
            outputFile = argv[++i];
        } 
        else {
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
}

int main(int argc, char* argv[]){
    using namespace CBZ;
    using namespace CBZ::Security;
    using namespace CBZ::Utils::IO;
    using namespace CBZ::PKCS;

    // file to read Private Key from
    std::string inputFile;
    // file to write into 
    std::string outputFile;

    handle_arguments(argc, argv, inputFile, outputFile);

    // Can be used for debugging in order not to input data each time the program is run
    #ifdef SKIP_INPUT_DEBUG
    std::vector<std::pair<std::string,std::string>> subject_info = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    std::vector<std::pair<std::string,std::string>> attributes = {{"1.2.840.113549.1.9.2", "example@agh.edu.pl"}};
    #else
    // If not skipping input just call the functions responsible for getting input from the user
    std::vector<std::pair<std::string, std::string>> subject_info = ask_for_subject_info();
    std::vector<std::pair<std::string, std::string>> attributes = ask_for_attrs_info();
    #endif

    // make the mpz_class to zeroize the memory when deallocating
    mpz_initialize_secure_free_policy();

    PKCS::RSAPrivateKey private_key;
    // decode the key from file
    try{
        private_key = PKCS::RSAPrivateKey(inputFile);
    } catch (const std::runtime_error& e) {
        std::cerr << "failed to decode file with private key" << std::endl;
        CBZ::Utils::print_nested(e, 0);
        exit(1);
    }
    // extract public key from private key
    const mpz_class& e = private_key.e();
    const mpz_class& n = private_key.n();

    // create certifcation request object using extracted public key and input from the user
    PKCS::CertificationRequest certification_request(
        std::move(subject_info),
        CSRSupportedAlgorithms::rsaEncryption, 
        std::move(n), 
        std::move(e),
        std::move(attributes),
        CSRSupportedAlgorithms::sha256WithRSAEncryption
    );

    // generate signature for the CSR
    certification_request.sign(private_key);

    // encode the CSR int DER
    std::vector<uint8_t> DER_encoding = certification_request.encode();
    // enocde DER encoding of CSR into base64
    std::string base64_output = Base64::encode(DER_encoding);
    // write base64 and DER encoded CSR into the file
    write_csr_to_file(base64_output, outputFile);

    // those are no longer need they can be zeroized
    secure_zero_memory(DER_encoding);
    secure_zero_memory(base64_output);

    std::cout << "VERIFICATION: " << std::boolalpha << certification_request.verify() << std::noboolalpha << std::endl;

    certification_request.to_asn1().print();

    try {
        PKCS::CertificationRequest request(certification_request.to_asn1());
        std::cout << std::endl << request << std::endl;
    } catch (const std::exception &e) {
        CBZ::Utils::print_nested(e);
    }
    
    return 0;
}
