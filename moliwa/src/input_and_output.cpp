#include "input_and_output.h"

// write the base64 encoded CSR into a file
void write_csr_to_file(const string &base64, const string &path){
    string header =     "-----BEGIN CERTIFICATE REQUEST-----\n";
    string trailer =    "-----END CERTIFICATE REQUEST-----\n";

    // Check if the file already exists; C++ 17 ONLY
    // https://stackoverflow.com/questions/12774207/fastest-way-to-check-if-a-file-exists-using-standard-c-c11-14-17-c
    // If the file exists, prompt the user to see if we can overwrite or not
    if(std::filesystem::exists(path)){
        string input;
        cout << "File already exists do you want to overwrite [y/N]: ";
        getline(cin, input);
        if(input[0] != 'y'){
            return;
        }
    }

    // Open the file and write the header into it
    ofstream ofile(path.c_str());
    if(!ofile.is_open()){
        throw MyError("write_csr_to_file: Could not open the file \"" + path + "\" for writing");
    }
    ofile << header;

    // counter used to add \n in after 64 chars
    int i = 0;
    // write letter by letter
    for(auto ch : base64){
        ofile << ch;
        i++;
        // after writing 64 chars add \n
        if(i == 64){
            i = 0;
            ofile << '\n';
        }
    }
    // add newline to last line if needed
    if(i != 0){
        ofile << '\n';
    }


    // Write the trailer and close the file
    ofile << trailer;
    ofile.close();

    cout << "Writting into the file: " << path << " done" << endl;
}

// Used to prompt user for data included in the CSR
// Note that in this function there 3 string vectors
// Items in those vectors have to be kept in this order
// as they were order this way to match one another
vector<pair<string,string>> ask_for_subject_info(){
    // Some values are compulsory
    // So here are the default values for certain fields
    vector<string> defaults({
        "PL",
        "Lesser Poland",
        "",
        "AGH",
        "",
        "",
        ""
    });

    // Messages that will be displayed to the user
    // Value in square brackets indicates the default value
    vector<string> messages({
        "Country Name (2 letter code) [" + defaults[0] + "]: ", 
        "State or Province Name (full name) [" + defaults[1] + "]: ",
        "Locality Name (eg, city) [" + defaults[2] + "]: ",
        "Organization Name (eg, company) [" + defaults[3] + "]: ",
        "Organizational Unit Name (eg, section) [" + defaults[4] + "]: ",
        "Common Name (e.g. server FQDN or YOUR name) [" + defaults[5] + "]: ",
        "Email Address [" + defaults[6] + "]: "
    });

    // OIDs indicating each field
    // https://oid-base.com/get/2.5.4
    // https://oid-base.com/cgi-bin/display?oid=1.2.840.113549.1.9.1&a=display
    vector<string> OIDs({
        "2.5.4.6",
        "2.5.4.8",
        "2.5.4.7",
        "2.5.4.10",
        "2.5.4.11",
        "2.5.4.3",
        "1.2.840.113549.1.9.1"
    });

    // these values must match because
    // these vectors must correspond to one another
    assert(OIDs.size() == messages.size());
    assert(OIDs.size() == defaults.size());

    // Message displayed at the start of the program
    string start_message = "You are about to be asked to enter information that\nwill be incorporated into your certificate request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\nThere are quite a few fields but you can leave some blank\nFor some fields there will be a default value,\nIf you enter '.' or nothing, the field will be left blank.\n--------------\n";
    cout << start_message;


    // will store the data
    vector<pair<string,string>> result;

    for(size_t i = 0; i < OIDs.size(); i++){
        string curr;

        // display i-th message
        cout << messages[i];

        getline(cin, curr);
        // There's a requirement for Country name to be 2 chars long

        // if there was no input or user input the dot "." just use defaults
        if(curr == "." || curr == "")
            curr = defaults[i];

        if(OIDs[i] == "2.5.4.6" && curr.size() != 2){
            cout << "Country Name must be 2 characters long" << endl;
            continue;
        }

        // don't add empty fields 
        if(curr != "")
            result.push_back({OIDs[i], curr});
    }

    return  result;
}

// Similar to ask_for_subject_info() however with less field
// also here all fields are optional so there are no default values
vector<pair<string,string>> ask_for_attrs_info(){
    // Messages that will be displayed to the user
    vector<string> messages({
        "A challenge password []: ",
        "An optional company name []: ",
    });

    // OIDs indicating each field
    // https://oid-base.com/cgi-bin/display?oid=1.2.840.113549.1.9&a=display
    vector<string> OIDs({
        "1.2.840.113549.1.9.7",
        "1.2.840.113549.1.9.2",
    });

    // these values must match because
    // these vectors must correspond to one another
    assert(OIDs.size() == messages.size());

    // message display to indicate to the user that they are to input attributes
    string start_message = "Please enter the following 'extra' attributes\nto be sent with your certificate request\n";
    cout << start_message;


    vector<pair<string,string>> result;
    for(size_t i = 0; i < OIDs.size(); i++){
        string curr;

        // display i-th message
        cout << messages[i];

        // not inputting anything is eqiuvalent to inputting a dot "."
        getline(cin, curr);
        if(curr == ".")
            curr = "";

        if(curr != "")
            result.push_back({OIDs[i], curr});
    }

    return  result;
}

// Just prints out how to use the program
void print_usage(const string &name) {
    cout << "Usage: " << name << " -in <inputfile> -out <outputfile>" << endl << endl;
}

// This function reads in the private key data from the file
// inspired by this:
// https://www.coniferproductions.com/posts/2022/10/25/reading-binary-files-cpp/
// I also tried to make zeroize all temporary buffers
// In future this will probably have to be remade to allow for JIT decryption
void read_privatekey_from_file(const string &path, vector<uint8_t> &return_buffer){
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
    zeroize(file_buffer);

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
    zeroize(base64_buffer);
}
