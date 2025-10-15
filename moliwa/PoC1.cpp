#include <fstream>

#include "mappings.h"
#include "encoding.h"
#include "openssl.h"
#include "csrclass.h"


using std::cout;
using std::ifstream;
using std::ofstream;
using std::cin;

void write_to_file(string base64, string name){
    string header = "-----BEGIN CERTIFICATE REQUEST-----\n";
    string trailer = "\n-----END CERTIFICATE REQUEST-----\n";
    ifstream ifile(name.c_str());
    if(ifile.good()){
        string input;
        cout << "File already exists do you want to overwrite [y/n]: ";
        cin >> input;
        if(input[0] != 'y')
            return;
    }
    ifile.close();
    ofstream ofile(name.c_str());
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


int main(){
    CertificationRequest CR(
        {
            {"2.5.4.6", "AU"},
            {"2.5.4.8", "Meow"},
            {"2.5.4.10", "OwO"}
        },
        mpz_class("29998119994325102740934263870958013612140431814369037011463274912294059725915571999656579689082023654213454599673104446299062998775654454664818234796765420706376318015050252611896155237284971055040520527836920955461385264904790561238796431677247296299293004972148559604927896465074978359662927084484054599897199780041432691778165333858202269177089052159546732091702726744098369502320116687031926157743163421445599275161041978215959837477409290452574595233521500081960750425613056457609724334979216999495957704779253573973290886660836435368236834936136544810438777458651258009796903224945302721241666216986167931835859"),
        mpz_class("65537"),
        {
            {"1.2.840.113549.1.9.2", "UwU"},
            {"1.2.840.113549.1.9.7", "Test"}
        }
    );

    
    vector<uint8_t> bytes = CR.encode("private-key.pem");
    string out = base64_encode(bytes);
    write_to_file(out, "test.pem");

 
    return 0;
}
