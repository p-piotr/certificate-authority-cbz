#ifndef INOUT_H
#define INOUT_H

#include <fstream>
#include <iostream>
#include <vector>
#include <filesystem>
#include <assert.h>
#include "myerror.h"
#include "decoding.h"

using std::ifstream;
using std::ofstream;
using std::string;
using std::cout;
using std::cin;
using std::endl;
using std::getline;
using std::pair;
using std::vector;

// this file contains functions related to input and output
// that include mostly interaction with the user and the external files

// This function is used to write Certificate Signing Request into the file
// It assumes that CSR have already beed DER encoded and base64 encoded
// @base64 - string to be written into the file
// @path - path to the file in write into
// If the file doesn't exist it will be created;
// If the file does exist the user will be prompted for permission to overwrite the file;
void write_csr_to_file(const string &base64, const string &path);

// This function is used to ask the user for information that will be include in the CSR
// e.g. Country, State/Province etc.
// Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
// return value: vector of pairs: OID + value_read_from_the_user
// e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
vector<pair<string,string>> ask_for_subject_info();

// This function is used to ask the user for information that will be include in the CSR
// however this time it's asking for attibutes e.g. challenge passoword
// Again a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
// return value: vector of pairs: OID + value_read_from_the_user
// e.g. { {"1.2.840.113549.1.9.7", "1234"} }
vector<pair<string,string>> ask_for_attrs_info();

// This function is used to write usage message
// @name - name of the current program i.e. argv[0]
void print_usage(const string &name);

// This function is used to read PrivateKey from file;
// As of now it only support PKCS#8 fromated file
// In future it will also implemented the JIT decryption of the PrivateKey file
// As of know it only reads from the file and base64 decodes it
// @path - path to the file
// @return_buffer - into this buffer DER encoded bytes from file will be written
void read_privatekey_from_file(const string &path, vector<uint8_t> &return_buffer);

#endif
