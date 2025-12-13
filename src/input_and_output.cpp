#include "input_and_output.h"
#include "utils/security.hpp"

// write_csr_to_file() has been moved to `src/utils/io.{h,cpp}`
// and is available as `CBZ::Utils::IO::write_csr_to_file()`

// ask_for_subject_info() has been moved to `src/utils/io.{h,cpp}`
// and is available as `CBZ::Utils::IO::ask_for_subject_info()`

// ask_for_attrs_info() has been moved to `src/utils/io.{h,cpp}`
// and is available as `CBZ::Utils::IO::ask_for_attrs_info()`

// prints out how to call the program
static void print_usage(const string& name) {
    cout << "Usage: " << name << " -in <inputfile> -out <outputfile>" << endl << endl;
}

// This function reads in the private key data from the file
// inspired by this:
// https://www.coniferproductions.com/posts/2022/10/25/reading-binary-files-cpp/
// I also tried to make zeroize all temporary buffers
// In future this will probably have to be remade to allow for JIT decryption
void read_privatekey_from_file(const string& path, vector<uint8_t>& return_buffer){
    using namespace CBZ::Security; // secure_zero_memory

    string header   = "-----BEGIN PRIVATE KEY-----\n";
    string trailer  = "-----END PRIVATE KEY-----\n";

    // get length of the file
    std::filesystem::path file_path{path};
    std::uintmax_t file_length = std::filesystem::file_size(file_path);

    // can't work with an empty file
    if(file_length == 0){
        throw MyError("read_privatekey_from_: File is empty");
    }

    // local buffer to store the bytes from the file
    vector<uint8_t> file_buffer(file_length);

    // std::ios_base::binary - open in binary mode
    ifstream input_file(path, std::ios_base::binary);

    // read data from file into the buffer
    // Note the reinterpret_cast must be used;
    // From what I gather online C++ treats uint8_t* and char* as unrelated types
    // this forces the use of reinterpret_cast
    // https://stackoverflow.com/questions/20930858/type-conversion-in-c-related-and-unrelated-types
    input_file.read(reinterpret_cast<char*>(file_buffer.data()), file_length);
    input_file.close();


    // check if header and trailer is correct
    if( !std::equal(header.begin(), header.end(), file_buffer.begin()) || 
        !std::equal(trailer.rbegin(), trailer.rend(), file_buffer.rbegin()) ){
        throw MyError("Unable to correctly interpret file: \"" + path + "\"; File must be in PKCS#8 format");
    }

    // strip the header also convert to string as needed by base64_decode
    string base64_buffer(file_buffer.begin()+ header.size(), file_buffer.end() - trailer.size());
    // file buffer can be zeroized
    secure_zero_memory(file_buffer);

    //remove the whitespaces
    size_t write_index = 0;
    for(size_t i = 0; i < base64_buffer.size(); i++){
        if(std::isspace(base64_buffer[i])){
            continue;
        }
        base64_buffer[write_index++] = base64_buffer[i];
    }
    base64_buffer.resize(write_index);

    // it base64_decode will write bytes directly into the target buffer
    base64_decode(base64_buffer, return_buffer);
    secure_zero_memory(base64_buffer);
}


// this function is used handle the command-line arguments
void handle_arguments(
    int argc, char** argv, 
    string& inputFile, string& outputFile
) {
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
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
