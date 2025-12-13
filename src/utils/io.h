#pragma once

#include <string>
#include <vector>
#include <utility>

namespace CBZ::Utils::IO {

	// This function is used to ask the user for information that will be include in the CSR
	// e.g. Country, State/Province etc.
	// Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
	// return value: vector of pairs: OID + value_read_from_the_user
	// e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
	std::vector<std::pair<std::string,std::string>> ask_for_subject_info();

	// This function is used to write Certificate Signing Request into the file
	// It assumes that CSR have already beed DER encoded and base64 encoded
	// @base64 - string to be written into the file
	// @path - path to the file in write into
	// If the file doesn't exist it will be created;
	// If the file does exist the user will be prompted for permission to overwrite the file;
	void write_csr_to_file(std::string const& base64, std::string const& path);

	// This function is used to ask the user for information that will be include in the CSR
	// however this time it's asking for attributes e.g. challenge passoword
	// Again a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
	// return value: vector of pairs: OID + value_read_from_the_user
	// e.g. { {"1.2.840.113549.1.9.7", "1234"} }
	std::vector<std::pair<std::string,std::string>> ask_for_attrs_info();

} // namespace CBZ::Utils::IO
