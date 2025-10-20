#include <fstream>

#include "mappings.h"
#include "decode-key.h"
#include "encoding.h"
#include "openssl.h"
#include "csrclass.h"


using std::cout;
using std::ifstream;
using std::getline;
using std::ofstream;
using std::cin;

void write_to_file(const string &base64, const string &path){
    string header = "-----BEGIN CERTIFICATE REQUEST-----\n";
    string trailer = "\n-----END CERTIFICATE REQUEST-----\n";
    ifstream ifile(path.c_str());
    if(ifile.good()){
        string input;
        cout << "File already exists do you want to overwrite [y/n]: ";
        cin >> input;
        if(input[0] != 'y')
            return;
    }
    ifile.close();
    ofstream ofile(path.c_str());
    ofile << header;

    int i = 0;
    for(auto ch : base64){
        ofile << ch;
        i++;
        if(i==64){
            i=0;
            ofile << '\n';
        }
    }
    ofile << trailer;
}

vector<pair<string,string>> ask_for_subject_info(){
    vector<string> messages({
        "Country Name (2 letter code) [PL]: ", 
        "State or Province Name (full name) [Lesser Poland]: ",
        "Locality Name (eg, city) []: ",
        "Organization Name (eg, company) [AGH]: ",
        "Organizational Unit Name (eg, section) []: ",
        "Common Name (e.g. server FQDN or YOUR name) []: ",
        "Email Address []: "
    });

    vector<string> OIDs({
        "2.5.4.6",
        "2.5.4.8",
        "2.5.4.7",
        "2.5.4.10",
        "2.5.4.11",
        "2.5.4.3",
        "1.2.840.113549.1.9.1"
    });

    vector<string> defaults({
        "PL",
        "Lesser Poland",
        "",
        "AGH",
        "",
        "",
        ""
    });

    string start_message = "You are about to be asked to enter information that\nwill be incorporated into your certificate request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\nThere are quite a few fields but you can leave some blank\nFor some fields there will be a default value,\nIf you enter '.' or nothing, the field will be left blank.\n--------------\n";
    cout << start_message;

    vector<pair<string,string>> result;

    for(int i = 0; i < messages.size(); i++){
        string curr;

        cout << messages[i];

        getline(cin, curr);
        if(curr == "." || curr == "")
            curr = defaults[i];

        if(curr != "")
            result.push_back({OIDs[i], curr});
    }

    return  result;
}

vector<pair<string,string>> ask_for_attrs_info(){
    vector<string> messages({
        "A challenge password []: ",
        "An optional company name []: ",
    });

    vector<string> OIDs({
        "1.2.840.113549.1.9.7",
        "1.2.840.113549.1.9.2",
    });


    string start_message = "Please enter the following 'extra' attributes\nto be sent with your certificate request\n";
    cout << start_message;

    vector<pair<string,string>> result;

    for(int i = 0; i < messages.size(); i++){
        string curr;

        cout << messages[i];

        getline(cin, curr);
        if(curr == ".")
            curr = "";

        if(curr != "")
            result.push_back({OIDs[i], curr});
    }

    return  result;
}

int main(int argc, char* argv[]){
    string inputFile;
    string outputFile;


    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];

        if (arg == "-in" && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (arg == "-out" && i + 1 < argc) {
            outputFile = argv[++i];
        } else {
            std::cerr << "Unknown flag or missing value: " << arg << endl;
        }
    }

    if (inputFile.empty()) {
        cout << "Enter path to file with private key: ";
        getline(cin, inputFile);
    }
    if (outputFile.empty()) {
        cout << "Enter output file name: ";
        getline(cin, outputFile);
    }
    cout << endl;

    vector<pair<string,string>> subject = ask_for_subject_info();
#ifdef DEBUG
    for(auto item : subject)
        cout << item.first << " " << item.second << endl;
#endif

    cout << endl;
    vector<pair<string,string>> attrs = ask_for_attrs_info();
#ifdef DEBUG
    for(auto item : attrs)
        cout << item.first << " " << item.second << endl;
    cout << endl;
#endif
    cout << endl;

    PrivateKeyInfo privateKeyInfo = read_from_file(inputFile); 
    PrivateKey PKey = privateKeyInfo.getPrivateKeyReference();

    CertificationRequest CR(
        subject,
        PKey.n,
        PKey.e,
        attrs
    );
    
    vector<uint8_t> bytes = CR.encode(PKey);
    string out = base64_encode(bytes);
    write_to_file(out, outputFile);

 
    return 0;
}
