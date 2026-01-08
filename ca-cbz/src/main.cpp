#include <iostream>
#include <vector>
#include <utility>
#include <fstream>
#include <sstream>
#include <random>
#include <string_view>
#include <unordered_map>
#include <type_traits>
#include "utils/io.h"
#include "pkcs/sign.h"
#include "pkcs/pkcs.h"
#include "utils/security.hpp"
#include "utils/utils.hpp"
#include "utils/base64.h"
#include "pkcs/private_key.h"
#include "pkcs/labels.h"
#include "hash/sha.h"

using namespace CBZ;
using namespace CBZ::Security;
using namespace CBZ::Utils::IO;
using namespace CBZ::PKCS;

using namespace std::literals;
using Arguments = std::unordered_map<std::string, std::string>; // argument key -> value mapping

std::string global_exe_name; // this gets initialized to argv[0] at the very beginning of main()

constexpr std::string_view usage = R"(
Commands:
  gen-self-signed-cert   Generate a self-signed root certificate
    --key <file>         Path to the RSA private key (REQUIRED)
    --out <file>         Output filename for the certificate (REQUIRED)
    --days <int>         Validity period in days (Default: 3650)

  gen-csr                Generate a Certificate Signing Request (CSR)
    --key <file>         Path to the RSA private key (REQUIRED)
    --out <file>         Output filename for the CSR (REQUIRED)

  gen-cert               Sign a CSR to generate a certificate
    --cacert <file>      Path to the issuer (CA) certificate (REQUIRED)
    --cakey <file>       Path to the issuer's RSA private key (REQUIRED)
    --csr <file>         Path to the subject's CSR (REQUIRED)
    --out <file>         Output filename for the certificate (REQUIRED)
    --days <int>         Validity period in days (Default: 3650)

General Options:
  --help                 Display this help message)"sv;

// helper function to join all string-alike types into one
template<typename... _Strings, typename = std::enable_if_t<(std::is_convertible_v<_Strings, std::string> && ...)>> // symfonia c++
std::string _concat_strings(_Strings... s) {
    std::string result = "";
    ((result += s), ...);
    return result;
}

// prints help
void print_help(const std::string& name) {
    std::cerr
        << "Usage: " << name << " <command> [options]\n"
        << usage << std::endl;
}

void print_error(const std::string error) {
    std::cerr << "[ERROR] " << error << "\n\n";
    print_help(global_exe_name);
}


mpz_class generate_id(mp_bitcnt_t bit_size) {
    // as per https://gmplib.org/manual/Random-State-Initialization
    // this will initialize a MT (Mersenne Twister) based generator
    thread_local std::unique_ptr<gmp_randclass> rng = []() {
        auto rng_ptr = std::make_unique<gmp_randclass>(gmp_randinit_default);
        std::random_device rd;
        rng_ptr->seed(rd());
        return rng_ptr;
    }();

    return rng->get_z_bits(bit_size);
}

// generates a PKCS::Certificate object based on the provided arguments (self-signed variant)
CBZ::PKCS::Certificate generate_self_signed_certificate(
    std::vector<std::pair<std::string, std::string>> subject_info,
    asn1date_t not_before,
    asn1date_t not_after,
    const RSAPrivateKey& subject_private_key
) {
    std::vector<uint8_t> subject_key_identifier(CBZ::SHA::SHA1::DIGEST_SIZE);
    std::vector<uint8_t> subject_public_key_bitstring = RSAPublicKey(subject_private_key).to_asn1().value();
    CBZ::SHA::SHA1::digest(subject_public_key_bitstring, subject_key_identifier.data());

    Certificate ca_certificate = Certificate(
        TBSCertificate(
            generate_id(160),
            AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption),
            subject_info,
            Validity(std::move(not_before), std::move(not_after)),
            subject_info,
            SubjectPublicKeyInfo(CSRSupportedAlgorithms::rsaEncryption, RSAPublicKey(subject_private_key)),
            {
                Extension(ExtensionSupportedIDs::subjectKeyIdentifier, false, ASN1OctetString(
                    subject_key_identifier // note that we can't move since we'll use it below, too
                ).encode()),
                Extension(ExtensionSupportedIDs::authorityKeyIdentifier, false, ASN1Sequence({
                    ASN1Object(CONTEXT_SPECIFIC0, subject_key_identifier) // it's a self-signed cert => aurhority=subject
                }).encode()),
                Extension(ExtensionSupportedIDs::basicConstraints, true, ASN1Sequence({ ASN1Boolean(true) }).encode())
            }
        ),
        AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption)
    );

    ca_certificate.sign(subject_private_key);
    return ca_certificate;
}

// generates a PKCS::Certificate object based on the provided arguments
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

    std::vector<uint8_t> subject_key_identifier(CBZ::SHA::SHA1::DIGEST_SIZE);
    std::vector<uint8_t> subject_public_key_bitstring = subject_pk_info.get_public_key().to_asn1().value();
    CBZ::SHA::SHA1::digest(subject_public_key_bitstring, subject_key_identifier.data());

    std::vector<uint8_t> authority_key_identifier(CBZ::SHA::SHA1::DIGEST_SIZE);
    std::vector<uint8_t> authority_public_key_bitstring = 
        ca_certificate.get_tbs_certificate().get_subject_public_key_info().get_public_key().to_asn1().value();
    CBZ::SHA::SHA1::digest(authority_public_key_bitstring, authority_key_identifier.data());

    Certificate subject_certificate = Certificate(
        TBSCertificate(
            generate_id(160),
            AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption),
            issuer,
            Validity(std::move(not_before), std::move(not_after)),
            subject,
            subject_pk_info,
            {
                Extension(ExtensionSupportedIDs::subjectKeyIdentifier, false, ASN1OctetString(
                    std::move(subject_key_identifier)
                ).encode()),
                Extension(ExtensionSupportedIDs::authorityKeyIdentifier, false, ASN1Sequence({
                    ASN1Object(CONTEXT_SPECIFIC0, std::move(authority_key_identifier))
                }).encode())
            }
        ),
        AlgorithmIdentifier(CSRSupportedAlgorithms::sha256WithRSAEncryption)
    );
    subject_certificate.sign(ca_private_key);
    return subject_certificate;
}

// 'main' function for gen-self-signed-cert global command
int gen_self_signed_cert(const Arguments& arguments) {
    std::string key_path;
    std::string out_cert_path;
    unsigned int days;

    // retrieve arguments

    // key_path
    try {
        key_path = arguments.at("--key");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--key'");
        return 1;
    }

    // out_cert_path
    try {
        out_cert_path = arguments.at("--out");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--out'");
        return 1;
    }

    // days
    if (!arguments.contains("--days")) {
        days = 3650; // default
    }
    else {
        try {
            days = static_cast<unsigned int>(std::stoul(arguments.at("--days")));
            // let's assume that the upper limit is 100 years
            if (days > 36500) {
                print_error("Parameter value out of range: '--days'");
                return 1;
            }
        }
        catch (const std::invalid_argument &e) {
            print_error("Invalid parameter value: '--days'");
            return 1;
        }
        catch (const std::out_of_range &e) {
            print_error("Parameter value out of range: '--days'");
            return 1;
        }
    }

    // perform actual actions

    std::vector<std::pair<std::string, std::string>> ca_subject_info = ask_for_subject_info();
    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::days(days);
    RSAPrivateKey ca_private_key;
    Certificate ca_certificate;
    std::vector<uint8_t> ca_certificate_asn1;
    std::string ca_certificate_asn1_b64;

    try {
        ca_private_key = RSAPrivateKey(key_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while opening the RSA key\n";
        return 1;
    }

    try {
        ca_certificate = generate_self_signed_certificate(
            ca_subject_info,
            not_before,
            not_after,
            ca_private_key
        );
    }
    catch (const std::exception& e) {
        std::cerr << "Error while generating a self-signed certificate\n";
        return 1;
    }

    try {
        ca_certificate_asn1 = ca_certificate.to_asn1().encode();
        ca_certificate_asn1_b64 = Base64::encode(ca_certificate_asn1);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while encoding a generated self-signed certificate\n";
        return 1;
    }

    try {
        write_pkcs_to_file(ca_certificate_asn1_b64, PKCSEntity::CERTIFICATE, out_cert_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while writing an encoded self-signed certificate to file\n";
        return 1;
    }

    CBZ::Security::secure_zero_memory(ca_certificate_asn1);
    CBZ::Security::secure_zero_memory(ca_certificate_asn1_b64);

    std::cout << "Certificate written to " << out_cert_path << "\n";
    // verify yourself with `openssl verify -CAfile cacert.pem cacert.pem`

    return 0;
}

// 'main' function for gen-csr global command
int gen_csr(const Arguments& arguments) {
    std::string key_path;
    std::string csr_out_path;

    // retrieve arguments

    // key_path
    try {
        key_path = arguments.at("--key");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--key'");
        return 1;
    }

    // out_cert_path
    try {
        csr_out_path = arguments.at("--out");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--out'");
        return 1;
    }
    
    // perform actual actions

    std::vector<std::pair<std::string, std::string>> subject_subject_info = ask_for_subject_info();
    std::vector<std::pair<std::string, std::string>> subject_attributes = ask_for_attrs_info();
    RSAPrivateKey subject_private_key;
    CertificationRequest subject_csr;
    std::vector<uint8_t> subject_csr_asn1;
    std::string subject_csr_asn1_b64;

    try {
        subject_private_key = RSAPrivateKey(key_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while opening the RSA key\n";
        return 1;
    }

    try {
        subject_csr = CertificationRequest(
            std::move(subject_subject_info),
            CSRSupportedAlgorithms::rsaEncryption,
            RSAPublicKey(subject_private_key),
            std::move(subject_attributes),
            CSRSupportedAlgorithms::sha256WithRSAEncryption
        );
        subject_csr.sign(subject_private_key);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while generating a CSR\n";
        return 1;
    }

    try {
        std::vector<uint8_t> subject_csr_asn1 = subject_csr.to_asn1().encode();
        std::string subject_csr_asn1_b64 = Base64::encode(subject_csr_asn1);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while encoding generated CSR\n";
        return 1;
    }

    try {
        write_pkcs_to_file(subject_csr_asn1_b64, PKCSEntity::CSR, csr_out_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while writing an encoded CSR to file\n";
        return 1;
    }

    CBZ::Security::secure_zero_memory(subject_csr_asn1);
    CBZ::Security::secure_zero_memory(subject_csr_asn1_b64);

    std::cout << "CSR written to " << csr_out_path << "\n";
    // verify yourself with `openssl req -in subcsr.pem -noout -verify`
    
    return 0;
}

// 'main' function for gen_cert global command
int gen_cert(const Arguments& arguments) {
    std::string ca_cert_path;
    std::string ca_key_path;
    std::string csr_path;
    std::string out_cert_path;
    int days;

    // retrieve arguments

    // ca_cert_path
    try {
        ca_cert_path = arguments.at("--cacert");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--cacert'");
        return 1;
    }

    // ca_key_path
    try {
        ca_key_path = arguments.at("--cakey");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--cakey'");
        return 1;
    }

    // out_cert_path
    try {
        out_cert_path = arguments.at("--out");
    }
    catch (const std::out_of_range& e) {
        print_error("Parameter must have a value: '--out'");
        return 1;
    }

    // days
    if (!arguments.contains("--days")) {
        days = 3650; // default
    }
    else {
        try {
            days = static_cast<unsigned int>(std::stoul(arguments.at("--days")));
            // let's assume that the upper limit is 100 years
            if (days > 36500) {
                print_error("Parameter value out of range: '--days'");
                return 1;
            }
        }
        catch (const std::invalid_argument &e) {
            print_error("Invalid parameter value: '--days'");
            return 1;
        }
        catch (const std::out_of_range &e) {
            print_error("Parameter value out of range: '--days'");
            return 1;
        }
    }

    // perform actual actions

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::days(days);
    RSAPrivateKey ca_private_key;
    Certificate ca_certificate;
    Certificate subject_certificate;
    CertificationRequest subject_csr;
    std::vector<uint8_t> subject_certificate_asn1;
    std::string subject_certificate_asn1_b64;

    try {
        ca_certificate = Certificate(ca_cert_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while opening the CA certificate\n";
        return 1;
    }

    try {
        subject_csr = CertificationRequest(csr_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while opening the CSR\n";
        return 1;
    }

    try {
        ca_private_key = RSAPrivateKey(ca_key_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while opening the RSA key\n";
        return 1;
    }

    try {
        subject_certificate = generate_certificate(
            subject_csr,
            not_before,
            not_after,
            ca_certificate,
            ca_private_key
        );
    }
    catch (const std::exception& e) {
        std::cerr << "Error while generating a certificate\n";
        return 1;
    }

    try {
        subject_certificate_asn1 = subject_certificate.to_asn1().encode();
        subject_certificate_asn1_b64 = Base64::encode(subject_certificate_asn1);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while encoding a generated certificate\n";
        return 1;
    }

    try {
        write_pkcs_to_file(subject_certificate_asn1_b64, PKCSEntity::CERTIFICATE, out_cert_path);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while writing encoded certificate to file\n";
        return 1;
    }

    CBZ::Security::secure_zero_memory(subject_certificate_asn1);
    CBZ::Security::secure_zero_memory(subject_certificate_asn1_b64);

    std::cout << "CA certificate written to " << out_cert_path << std::endl;
    // verify yourself with `openssl verify -CAfile cacert.pem subcert.pem`

    return 0;
}

// this function is used handle the command-line arguments
int handle_arguments(int argc, char** argv) {
    Arguments arguments;

    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    std::string command = argv[1];
    if (command == "-h" || command == "--help") {
        print_help(argv[0]);
        return 0;
    }

    int i = 2;
    while (i+1 < argc) {
        if (arguments.contains(argv[i])) {
            print_error(_concat_strings("Argument '", argv[i], "' redefined"));
            return 1;
        }
        arguments.emplace(argv[i], argv[i+1]);
        i += 2;
    }

    if (i+1 == argc) {
        print_error(_concat_strings("Argument '", argv[i], "' without a value"));
        return 1;
    }

    if (command == "gen-self-signed-cert")  return gen_self_signed_cert(arguments);
    if (command == "gen-csr")               return gen_csr(arguments);
    if (command == "gen-cert")              return gen_cert(arguments);

    print_error(_concat_strings("Command '", command, "' does not exist"));
    return 1;
}

int main(int argc, char* argv[]){
    global_exe_name = argv[0];

    // make the mpz_class to zeroize the memory when deallocating
    mpz_initialize_secure_free_policy();

    return handle_arguments(argc, argv);
}
