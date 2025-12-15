#include <iostream>
#include <string>
#include <filesystem>
#include <vector>
#include <fstream>
#include <cassert>
#include <stdexcept>
#include <termios.h>
#include <unistd.h>
#include "utils/io.h"

using std::string;
using std::vector;
using std::pair;
using std::cout;
using std::cin;
using std::endl;
using std::getline;

namespace CBZ::Utils::IO {

    // Enables (or disables) stdin echo
    // Temporarily disable while prompting for a passphrase or other secrets
    void set_stdin_echo(bool enable) {
        struct termios tty;
        tcgetattr(STDIN_FILENO, &tty);

        if (!enable)
            tty.c_lflag &= ~ECHO;
        else
            tty.c_lflag |= ECHO;

        tcsetattr(STDIN_FILENO, TCSANOW, &tty);
    }

    std::string ask_for_password() {
        std::string passphrase;
        std::cout << std::endl << "Enter passphrase: ";
        set_stdin_echo(false);
        std::cin >> passphrase;
        set_stdin_echo(true);
        std::cout << std::endl;
        return passphrase;
    }

    // This function is used to ask the user for information that will be include in the CSR
    // e.g. Country, State/Province etc.
    // Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
    // return value: vector of pairs: OID + value_read_from_the_user
    // e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
    std::vector<std::pair<std::string,std::string>> ask_for_subject_info(){
        vector<string> defaults({
            "PL",
            "Lesser Poland",
            "",
            "AGH",
            "",
            "",
            ""
        });

        vector<string> messages({
            "Country Name (2 letter code) [" + defaults[0] + "]: ", 
            "State or Province Name (full name) [" + defaults[1] + "]: ",
            "Locality Name (eg, city) [" + defaults[2] + "]: ",
            "Organization Name (eg, company) [" + defaults[3] + "]: ",
            "Organizational Unit Name (eg, section) [" + defaults[4] + "]: ",
            "Common Name (e.g. server FQDN or YOUR name) [" + defaults[5] + "]: ",
            "Email Address [" + defaults[6] + "]: "
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

        assert(OIDs.size() == messages.size());
        assert(OIDs.size() == defaults.size());

        string start_message = "You are about to be asked to enter information that\nwill be incorporated into your certificate request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\nThere are quite a few fields but you can leave some blank\nFor some fields there will be a default value,\nIf you enter '.' or nothing, the field will be left blank.\n--------------\n";
        cout << start_message;

        vector<pair<string,string>> result;

        for(size_t i = 0; i < OIDs.size(); i++){
            string curr;
            cout << messages[i];
            getline(cin, curr);

            if(curr == "." || curr == "")
                curr = defaults[i];

            if(OIDs[i] == "2.5.4.6" && curr.size() != 2){
                cout << "Country Name must be 2 characters long" << std::endl;
                continue;
            }

            if(curr != "")
                result.push_back({OIDs[i], curr});
        }
        cout << std::endl;

        return result;
    }

    // This function is used to write Certificate Signing Request into a file
    // It assumes that CSR have already beed DER encoded and base64 encoded
    // @base64 - string to be written into the file
    // @path - path to the file in write into
    // If the file doesn't exist it will be created;
    // If the file does exist the user will be prompted for permission to overwrite the file;
    void write_csr_to_file(std::string const& base64, std::string const& path){
        std::string header =     "-----BEGIN CERTIFICATE REQUEST-----\n";
        std::string trailer =    "-----END CERTIFICATE REQUEST-----\n";

        if(std::filesystem::exists(path)){
            std::string input;
            std::cout << "File already exists do you want to overwrite [y/N]: ";
            // clear the stdin buffer as some leftovers from previous inputs could remain
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::getline(std::cin, input);
            if(input.empty() || input[0] != 'y'){
                return;
            }
        }

        std::ofstream ofile(path.c_str());
        if(!ofile.is_open()){
            throw std::runtime_error("write_csr_to_file: Could not open the file \"" + path + "\" for writing");
        }
        ofile << header;

        int i = 0;
        for(auto ch : base64){
            ofile << ch;
            i++;
            if(i == 64){
                i = 0;
                ofile << '\n';
            }
        }
        if(i != 0){
            ofile << '\n';
        }

        ofile << trailer;
        ofile.close();

        std::cout << "Writting into the file: " << path << " done" << std::endl;
    }

    // This function is used to ask the user for information that will be include in the CSR
    // however this time it's asking for attibutes e.g. challenge passoword
    // Again a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
    // return value: vector of pairs: OID + value_read_from_the_user
    // e.g. { {"1.2.840.113549.1.9.7", "1234"} }
    std::vector<std::pair<std::string,std::string>> ask_for_attrs_info(){
        // Messages that will be displayed to the user
        vector<string> messages({
            "A challenge password []: ",
            "An optional company name []: ",
        });

        // OIDs indicating each field
        vector<string> OIDs({
            "1.2.840.113549.1.9.7",
            "1.2.840.113549.1.9.2",
        });

        assert(OIDs.size() == messages.size());

        string start_message = "Please enter the following 'extra' attributes\nto be sent with your certificate request\n";
        cout << start_message;

        vector<pair<string,string>> result;
        for(size_t i = 0; i < OIDs.size(); i++){
            string curr;
            cout << messages[i];
            getline(cin, curr);
            if(curr == ".")
                curr = "";
            if(curr != "")
                result.push_back({OIDs[i], curr});
        }
        cout << endl;

        return result;
    }

} // namespace CBZ::Utils::IO
