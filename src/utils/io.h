#pragma once

#include <string>
#include <vector>
#include <utility>

namespace CBZ::Utils::IO {

    // Enables (or disables) stdin echo
    // Temporarily disable while prompting for a passphrase or other secrets
    void set_stdin_echo(bool enable = true);

	// Asks for password, disabling the terminal echo during the process
    std::string ask_for_password();

	// This function is used to ask the user for information that will be included in the CSR
	// e.g. Country, State/Province etc.
	// Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
	// return value: vector of pairs: OID + value_read_from_the_user
	// e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
	std::vector<std::pair<std::string,std::string>> ask_for_subject_info();

	// This function is used to ask the user for information that will be included in the CSR
	// however this time it's asking for attributes e.g. challenge passoword
	// Again a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
	// return value: vector of pairs: OID + value_read_from_the_user
	// e.g. { {"1.2.840.113549.1.9.7", "1234"} }
	std::vector<std::pair<std::string,std::string>> ask_for_attrs_info();

    enum class PKCSEntity {
        PRIVATE_KEY,
        ENCRYPTED_PRIVATE_KEY,
        CSR,
        CERTIFICATE
    };
    void write_pkcs_to_file(const std::string& base64, PKCSEntity entity, const std::string& filepath);
}
