#ifndef INOUT_H
#define INOUT_H

#include "decoding.h"


// this file contains functions related to input and output
// that include mostly interaction with the user and the external files

// write_csr_to_file moved to `utils/io.h` (CBZ::Utils::IO::write_csr_to_file)

// This function is used to ask the user for information that will be include in the CSR
// e.g. Country, State/Province etc.
// Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
// return value: vector of pairs: OID + value_read_from_the_user
// e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
// ask_for_subject_info moved to `utils/io.h` (CBZ::Utils::IO::ask_for_subject_info)

// ask_for_attrs_info moved to `utils/io.h` (CBZ::Utils::IO::ask_for_attrs_info)

// This function is used to read PrivateKey from file;
// As of now it only support PKCS#8 fromated file
// In future it will also implemented the JIT decryption of the PrivateKey file
// As of know it only reads from the file and base64 decodes it
// @path - path to the file
// @return_buffer - into this buffer DER encoded bytes from file will be written
void read_privatekey_from_file(const string& path, vector<uint8_t>& return_buffer);

// this function is called immediately after the program is run
// it handles command-line arguments and prints usage message if program was run incorrectly
// @argc - value of argc
// @argv - pointer ro argv
// @inputFile - string that holds path from which Private Key will be read
// @outputFile - string that holds path into which CSR will be written
// more parametrs should be added if 
void handle_arguments(int argc, char** argv, string& inputFile, string& outputFile);

#endif
