#include <iostream>
#include <vector>
#include <utility>
#include <fstream>
#include <sstream>
#include "utils/io.h"
#include "pkcs/sign.h"
#include "pkcs/pkcs.h"
#include "utils/security.hpp"
#include "utils/utils.hpp"
#include "utils/base64.h"
#include "pkcs/private_key.h"
#include "pkcs/labels.h"

using namespace CBZ;
using namespace CBZ::Security;
using namespace CBZ::Utils::IO;
using namespace CBZ::PKCS;

// prints out how to call the program
static void print_usage(const std::string& name) {
    std::cout << "Usage: " << name << '\n'
        << "\t -privca <ca private key>\n"
        << "\t -privsub <subject private key>\n"
        << "\t -cacert <out ca certificate>\n"
        << "\t -subcsr <out subject CSR>\n"
        << "\t -subcert <out subject certificate>\n"
        << std::endl;
}

// this function is used handle the command-line arguments
void handle_arguments(
    int argc, char** argv, 
    std::string& ca_private_key, std::string& subject_private_key,
    std::string& ca_certificate, std::string& subject_csr,
    std::string& subject_certificate
) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-privca" && i + 1 < argc) {
            ca_private_key = argv[++i];
        } 
        else if (arg == "-privsub" && i + 1 < argc) {
            subject_private_key = argv[++i];
        }
        else if (arg == "-cacert" && i + 1 < argc) {
            ca_certificate = argv[++i];
        }
        else if (arg == "-subcsr" && i + 1 < argc) {
            subject_csr = argv[++i];
        }
        else if (arg == "-subcert" && i + 1 < argc) {
            subject_certificate = argv[++i];
        }
        else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    // if user forgot some parameters print usage message and exit 
    if (ca_private_key.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
    if (subject_private_key.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
    if (ca_certificate.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
    if (subject_csr.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
    if (subject_certificate.empty()) {
        print_usage(argv[0]);
        exit(1);
    }
}

enum class PKCSEntity {
    PRIVATE_KEY,
    ENCRYPTED_PRIVATE_KEY,
    CSR,
    CERTIFICATE
};
// modify that function so it asks whether to overwrite if the file exists
void write_pkcs_to_file(const ASN1Object& root_object, PKCSEntity entity, std::string filepath) {
    const std::string* header;
    const std::string* footer;

    switch (entity) {
        case PKCSEntity::PRIVATE_KEY:
            header = &Labels::private_key_header;
            footer = &Labels::private_key_footer;
            break;
        case PKCSEntity::ENCRYPTED_PRIVATE_KEY:
            header = &Labels::encrypted_private_key_header;
            footer = &Labels::encrypted_private_key_footer;
            break;
        case PKCSEntity::CSR:
            header = &Labels::csr_header;
            footer = &Labels::csr_footer;
            break;
        case PKCSEntity::CERTIFICATE:
            header = &Labels::certificate_header;
            footer = &Labels::certificate_footer;
            break;
        default:
            throw std::runtime_error("[write_pkcs_to_file] Unknown type");
    }

    std::vector<uint8_t> asn1_encoded = root_object.encode();
    std::string base64 = Base64::encode(asn1_encoded);
    std::ofstream entity_of(filepath); // this may leak data but i don't care yet
    entity_of << *header << base64 << '\n' << *footer;
    entity_of.flush();

    secure_zero_memory(asn1_encoded);
    secure_zero_memory(base64);
}

CBZ::PKCS::Certificate generate_self_signed_certificate(
    std::vector<std::pair<std::string, std::string>> subject_info,
    asn1date_t not_before,
    asn1date_t not_after,
    const RSAPrivateKey& subject_private_key
) {
    Certificate ca_certificate = Certificate(
        TBSCertificate(
            mpz_class("399428965409152426586363763062079902659407181241"), // change that ID to be auto-generated
            AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption),
            subject_info,
            Validity(std::move(not_before), std::move(not_after)),
            subject_info,
            SubjectPublicKeyInfo(CSRSupportedAlgorithms::rsaEncryption, RSAPublicKey(subject_private_key)),
            {
                // change those arbitrary values to something more meaningful
                Extension(ExtensionSupportedIDs::subjectKeyIdentifier, false, ASN1OctetString({
                    0x69, 0x69, 0xC6, 0x4D, 0x77, 0xAA, 0xCA, 0x07, 0xE2, 0xA1,
                    0x95, 0x0E, 0x5A, 0x3C, 0xBF, 0xF9, 0xED, 0xB4, 0xD3, 0x19
                }).encode()),
                // the same as above
                Extension(ExtensionSupportedIDs::authorityKeyIdentifier, false, ASN1Sequence({
                    ASN1Object(CONTEXT_SPECIFIC0, std::vector<uint8_t>{
                        0x69, 0x69, 0xC6, 0x4D, 0x77, 0xAA, 0xCA, 0x07, 0xE2, 0xA1,
                        0x95, 0x0E, 0x5A, 0x3C, 0xBF, 0xF9, 0xED, 0xB4, 0xD3, 0x19
                    })
                }).encode()),
                Extension(ExtensionSupportedIDs::basicConstraints, true, ASN1Sequence({ ASN1Boolean(true) }).encode())
            }
        ),
        AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption)
    );

    ca_certificate.sign(subject_private_key);
    return ca_certificate;
}

CBZ::PKCS::Certificate generate_certificate(
    const CertificationRequest& csr,
    asn1date_t not_before,
    asn1date_t not_after,
    const Certificate& ca_certificate,
    const RSAPrivateKey& ca_private_key
) {
    if (!csr.verify()) {
        throw std::runtime_error("[generate_certificate] CSR verification failure!");
    }

    const auto& subject = csr.get_certification_request_info().get_subject_name();
    const auto& subject_pk_info = csr.get_certification_request_info().get_subject_pkinfo();
    const auto& issuer = ca_certificate.get_tbs_certificate().get_subject();

    Certificate subject_certificate = Certificate(
        TBSCertificate(
            mpz_class("277784947810927137764440751906145424334048061781"), // change that ID to be auto-generated
            AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption),
            issuer,
            Validity(std::move(not_before), std::move(not_after)),
            subject,
            subject_pk_info,
            {
                // change those arbitrary values to something more meaningful
                Extension(ExtensionSupportedIDs::subjectKeyIdentifier, false, ASN1OctetString({
                    0x62, 0x51, 0x4F, 0x94, 0x93, 0x14, 0x4A, 0xB9, 0x8F, 0x9F,
                    0xCE, 0x1E, 0xA8, 0x8B, 0x32, 0x95, 0x0D, 0xD8, 0x0A, 0x00
                }).encode()),
                // the same as above
                Extension(ExtensionSupportedIDs::authorityKeyIdentifier, false, ASN1Sequence({
                    ASN1Object(CONTEXT_SPECIFIC0, std::vector<uint8_t>{
                        0x69, 0x69, 0xC6, 0x4D, 0x77, 0xAA, 0xCA, 0x07, 0xE2, 0xA1,
                        0x95, 0x0E, 0x5A, 0x3C, 0xBF, 0xF9, 0xED, 0xB4, 0xD3, 0x19
                    })
                }).encode())
            }
        ),
        AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption)
    );
    subject_certificate.sign(ca_private_key);
    return subject_certificate;
}

int main(int argc, char* argv[]){
    std::string ca_private_key_filepath;
    std::string subject_private_key_filepath;
    std::string ca_certificate_filepath;
    std::string subject_csr_filepath;
    std::string subject_certificate_filepath;

    // make the mpz_class to zeroize the memory when deallocating
    mpz_initialize_secure_free_policy();

    handle_arguments(
        argc,
        argv,
        ca_private_key_filepath,
        subject_private_key_filepath,
        ca_certificate_filepath,
        subject_csr_filepath,
        subject_certificate_filepath
    );

    RSAPrivateKey ca_private_key;
    RSAPrivateKey subject_private_key;
    // decode the key from file
    try{
        ca_private_key = RSAPrivateKey(ca_private_key_filepath);
        subject_private_key = RSAPrivateKey(subject_private_key_filepath);
    } catch (const std::runtime_error& e) {
        std::cerr << "failed to decode file with private key\n";
        CBZ::Utils::print_nested(e, 0);
        exit(1);
    }

    auto now = std::chrono::system_clock::now();
    auto in_5_years = [&]() {
        auto date_part = std::chrono::floor<std::chrono::days>(now);
        auto time_of_day = now - date_part;
        std::chrono::year_month_day ymd{ date_part };
        ymd += std::chrono::years(5);
        if (!ymd.ok()) {
            ymd = ymd.year() / ymd.month() / std::chrono::last;
        }
        auto future_tp = std::chrono::sys_days{ymd} + time_of_day;
        return future_tp;
    }();

    // std::cout << now << std::endl;
    // std::cout << in_5_years << std::endl;
    // auto not_before = []() {
    //     std::istringstream in("2026-03-01 14:22:27 +0000");
    //     std::chrono::sys_time<std::chrono::seconds> tp;
    //     in >> std::chrono::parse("%Y-%d-%m %T %z", tp);
    //     return std::chrono::floor<std::chrono::seconds>(tp);
    // }();
    // auto not_after = []() {
    //     std::istringstream in("2036-01-01 14:22:27 +0000");
    //     std::chrono::sys_time<std::chrono::seconds> tp;
    //     in >> std::chrono::parse("%Y-%d-%m %T %z", tp);
    //     return std::chrono::floor<std::chrono::seconds>(tp);
    // }();


    // generate the CA certificate (self-signed)

    std::cout << "Generating CA certificate...\n";
    std::cout << "Gathering CA information...\n\n";
    // Can be used for debugging in order not to input data each time the program is run
    #ifdef SKIP_INPUT_DEBUG
    std::vector<std::pair<std::string,std::string>> ca_subject_info = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    #else
    // If not skipping input just call the functions responsible for getting input from the user
    std::vector<std::pair<std::string, std::string>> ca_subject_info = ask_for_subject_info();
    #endif

    Certificate ca_certificate = generate_self_signed_certificate(
        ca_subject_info,
        now,
        in_5_years,
        ca_private_key
    );

    write_pkcs_to_file(ca_certificate.to_asn1(), PKCSEntity::CERTIFICATE, ca_certificate_filepath);
    std::cout << "CA certificate written to " << ca_certificate_filepath << "\n";
    std::cout << "Signature verification: "
        << std::boolalpha << ca_certificate.verify(ca_certificate) << std::noboolalpha << "\n\n";
    // verify yourself with `openssl verify -CAfile cacert.pem cacert.pem`

    // generate the entity CSR
    std::cout << "Generating entity CSR...\n";
    std::cout << "Gathering entity information...\n\n";
    #ifdef SKIP_INPUT_DEBUG
    std::vector<std::pair<std::string,std::string>> subject_subject_info = { {"2.5.4.6", "PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} };
    std::vector<std::pair<std::string,std::string>> subject_attributes = {{"1.2.840.113549.1.9.2", "example@agh.edu.pl"}};
    #else
    // If not skipping input just call the functions responsible for getting input from the user
    std::vector<std::pair<std::string, std::string>> subject_subject_info = ask_for_subject_info();
    std::vector<std::pair<std::string, std::string>> subject_attributes = ask_for_attrs_info();
    #endif

    CertificationRequest subject_csr(
        std::move(subject_subject_info),
        CSRSupportedAlgorithms::rsaEncryption,
        RSAPublicKey(subject_private_key),
        std::move(subject_attributes),
        CSRSupportedAlgorithms::sha256WithRSAEncryption
    );
    subject_csr.sign(subject_private_key);

    write_pkcs_to_file(subject_csr.to_asn1(), PKCSEntity::CSR, subject_csr_filepath);
    std::cout << "CA certificate written to " << subject_csr_filepath << "\n";
    std::cout << "Signature verification: "
        << std::boolalpha << subject_csr.verify() << std::noboolalpha << "\n\n";
    // verify yourself with `openssl req -in subcsr.pem -noout -verify`

    // generate the subject certificate
    Certificate ca_certificate2 = Certificate(ca_certificate_filepath);
    CertificationRequest subject_csr2 = CertificationRequest(subject_csr_filepath);

    Certificate subject_certificate = generate_certificate(
        subject_csr2,
        now,
        in_5_years,
        ca_certificate2,
        ca_private_key
    );

    write_pkcs_to_file(subject_certificate.to_asn1(), PKCSEntity::CERTIFICATE, subject_certificate_filepath);
    std::cout << "CA certificate written to " << subject_certificate_filepath << std::endl;
    std::cout << "Signature verification: "
        << std::boolalpha << subject_certificate.verify(ca_certificate) << std::noboolalpha << std::endl;
    // verify yourself with `openssl verify -CAfile cacert.pem subcert.pem`


    // TODO:
    // 1. fix arbitrary values used in generate_self_signed_certificate and generate_certificate
    // 2. move write_pkcs_to_file to a more sensible place (like utils/io.cpp)

    return 0;
}
