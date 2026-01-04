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
#include "pkcs/labels.h"

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

        // clear the stdin buffer
        // cin>>operator can leave some leftover characters
        // we want to clear them here so it won't cause some input to be skipped later
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        return passphrase;
    }

    // This function is used to ask the user for information that will be include in the CSR
    // e.g. Country, State/Province etc.
    // Pretty much a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
    // return value: vector of pairs: OID + value_read_from_the_user
    // e.g. { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} }
    std::vector<std::pair<std::string,std::string>> ask_for_subject_info(){
        std::vector<std::string> defaults({
            "PL",
            "Lesser Poland",
            "",
            "AGH",
            "",
            "",
            ""
        });

        std::vector<std::string> messages({
            "Country Name (2 letter code) [" + defaults[0] + "]: ", 
            "State or Province Name (full name) [" + defaults[1] + "]: ",
            "Locality Name (eg, city) [" + defaults[2] + "]: ",
            "Organization Name (eg, company) [" + defaults[3] + "]: ",
            "Organizational Unit Name (eg, section) [" + defaults[4] + "]: ",
            "Common Name (e.g. server FQDN or YOUR name) [" + defaults[5] + "]: ",
            "Email Address [" + defaults[6] + "]: "
        });

        std::vector<std::string> OIDs({
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

        std::string start_message = "You are about to be asked to enter information that\nwill be incorporated into your certificate request.\nWhat you are about to enter is what is called a Distinguished Name or a DN.\nThere are quite a few fields but you can leave some blank\nFor some fields there will be a default value,\nIf you enter '.' or nothing, the field will be left blank.\n--------------\n";
        std::cout << start_message;

        std::vector<std::pair<std::string,std::string>> result;

        for(size_t i = 0; i < OIDs.size(); i++){
            std::string curr;
            std::cout << messages[i];
            getline(std::cin, curr);

            if(curr == "." || curr == "")
                curr = defaults[i];

            if(OIDs[i] == "2.5.4.6" && curr.size() != 2){
                std::cout << "Country Name must be 2 characters long" << std::endl;
                continue;
            }

            if(curr != "")
                result.push_back({OIDs[i], curr});
        }
        std::cout << std::endl;

        return result;
    }

    // This function is used to ask the user for information that will be included in the CSR
    // however this time it's asking for attibutes e.g. challenge passoword
    // Again a copy of what "$openssl req -new -key [keyfile] -out [outfile]" command asks for
    // return value: vector of pairs: OID + value_read_from_the_user
    // e.g. { {"1.2.840.113549.1.9.7", "1234"} }
    std::vector<std::pair<std::string,std::string>> ask_for_attrs_info(){
        // Messages that will be displayed to the user
        std::vector<std::string> messages({
            "A challenge password []: ",
            "An optional company name []: ",
        });

        // OIDs indicating each field
        std::vector<std::string> OIDs({
            "1.2.840.113549.1.9.7",
            "1.2.840.113549.1.9.2",
        });

        assert(OIDs.size() == messages.size());

        std::string start_message = "Please enter the following 'extra' attributes\nto be sent with your certificate request\n";
        std::cout << start_message;

        std::vector<std::pair<std::string,std::string>> result;
        for(size_t i = 0; i < OIDs.size(); i++){
            std::string curr;
            std::cout << messages[i];
            getline(std::cin, curr);
            if(curr == ".")
                curr = "";
            if(curr != "")
                result.push_back({OIDs[i], curr});
        }
        std::cout << std::endl;

        return result;
    }

    // modify that function so it asks whether to overwrite if the file exists
    void write_pkcs_to_file(const std::string& base64, PKCSEntity entity, std::string filepath) {
        using namespace CBZ::PKCS;

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

        std::ofstream entity_of(filepath); // this may leak data but i don't care yet
        entity_of << *header << base64 << '\n' << *footer;
        entity_of.flush();
    }
} // namespace CBZ::Utils::IO
