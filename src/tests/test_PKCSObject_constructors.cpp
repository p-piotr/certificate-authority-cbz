#include <iostream>
#include <cassert>
#include <utility>
#include <vector>
#include "utils/utils.hpp"
#include "pkcs/pkcs.h"

using namespace CBZ::PKCS;
using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::pair;

int main(){
    using namespace CBZ::Utils;

    cout << "\n--- AttributeTypeAndValue Tests ---\n";

    // Constructors
    AttributeTypeAndValue ATAV1;
    string val1("2.5.4.6");
    string val2("PL");
    AttributeTypeAndValue ATAV2(val1, val2);
    AttributeTypeAndValue ATAV3{"2.5.4.6", "PL"};
    AttributeTypeAndValue ATAV4("2.5.4.6", "PL", PRINTABLE_STRING);
    AttributeTypeAndValue ATAV5{"2.5.4.6", "PL", PRINTABLE_STRING};

    // Copy / Move
    AttributeTypeAndValue ATAV_empty;
    AttributeTypeAndValue ATAV_copy(ATAV2);
    AttributeTypeAndValue ATAV_assign;
    ATAV_assign = ATAV3;
    AttributeTypeAndValue ATAV_move(std::move(ATAV4));
    AttributeTypeAndValue ATAV_move_assign;
    ATAV_move_assign = std::move(ATAV5);

    // Print
    cout << ATAV1 << endl;
    cout << ATAV2 << endl;
    cout << ATAV_copy << endl;
    cout << ATAV_move << endl;

    // Assertions
    assert(ATAV2.get_type() == "2.5.4.6");
    assert(ATAV2.get_value() == "PL");
    assert(ATAV_copy.get_value() == ATAV2.get_value());

    cout << "AttributeTypeAndValue tests done.\n";

    cout << "\n--- RelativeDistinguishedName Tests ---\n";

    RelativeDistinguishedName RDN_empty;
    RelativeDistinguishedName RDN_single{ATAV1};
    RelativeDistinguishedName RDN_multiple({ATAV2, ATAV3});
    RelativeDistinguishedName RDN_initializer_list{{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}};
    RelativeDistinguishedName RDN_copy(RDN_single);
    RelativeDistinguishedName RDN_move(std::move(RDN_multiple));
    RelativeDistinguishedName RDN_assign;
    RDN_assign = RDN_initializer_list;
    RelativeDistinguishedName RDN_move_assign;
    RDN_move_assign = std::move(RDN_copy);

    // Edge cases
    RelativeDistinguishedName RDN_edge1{{"", ""}};
    RelativeDistinguishedName RDN_edge2{{"0.0", "X"}};
    RelativeDistinguishedName RDN_edge3{{"2.999.4.0", "Y"}};

    // Print
    cout << RDN_empty << endl;
    cout << RDN_single << endl;
    cout << RDN_initializer_list << endl;
    cout << RDN_edge1 << endl;
    cout << RDN_edge2 << endl;

    // Assertions
    assert(RDN_single.get_attributes().size() == 1);
    assert(RDN_initializer_list.get_attributes().size() == 2);
    assert(!RDN_edge1.get_attributes().empty());

    cout << "RelativeDistinguishedName tests done.\n";

    cout << "\n--- rdnSequence Tests ---\n";

    vector<pair<string,string>> vec8{{"2.5.4.6","PL"}, {"2.5.4.10","AGH"}};
    RDNSequence rdns1(vec8);

    RDNSequence rdnS_empty;
    RDNSequence rdnS_single({RDN_single});
    RDNSequence rdnS_multiple({RDN_initializer_list, RDN_edge2, RDN_edge3});
    RDNSequence rdnS_copy(rdnS_single);
    RDNSequence rdnS_move(std::move(rdnS_multiple));
    RDNSequence rdnS_assign;
    rdnS_assign = rdnS_copy;
    RDNSequence rdnS_move_assign;
    rdnS_move_assign = std::move(rdnS_assign);

    // Edge case: empty RDN in sequence
    RDNSequence rdnS_edge{RDN_empty, RDN_single};

    // Print
    cout << rdnS_empty << endl;
    cout << rdnS_single << endl;
    cout << rdnS_move << endl;
    cout << rdnS_edge << endl;

    // Assertions
    assert(rdnS_single.get_rdn_sequence().size() == 1);
    assert(rdnS_move.get_rdn_sequence().size() == 3);
    assert(!rdnS_edge.get_rdn_sequence().empty());
    RDNSequence rdnS1 { {"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"} };
    RDNSequence rdnS2 { {{"2.5.4.6", "PL"}, {"2.5.4.10", "AGH"}} };
    cout << rdnS1 << endl;
    cout << rdnS2 << endl;

    cout << "rdnSequence tests done.\n";

    // i removed this constructor since there's no practical usage for it
    // except for this test
    // AlgorithmIdentifier AI1("1.2.840.113549.1.1.1");
    AlgorithmIdentifier AI2(CSRSupportedAlgorithms::rsaEncryption);
    //cout << AI1 << endl;
    cout << AI2 << endl;

    RSAPublicKey PK1("1234123412341234123412341234123413241234134", "12384123841239412342314823041234218");
    mpz_class test2("9999999999999999999999999999999999999999999999999999999999");
    mpz_class test1("23434343434343434");
    RSAPublicKey PK2(test1, test2);
    cout << PK1 << endl;
    cout << PK2 << endl;

    SubjectPublicKeyInfo SPKI1;
    //SubjectPublicKeyInfo SPKI2(AlgorithmIdentifier("1.2.840.113549.1.1.1"), RSAPublicKey("1234", "1234"));
    //SubjectPublicKeyInfo SPKI3("1.2.840.113549.1.1.1", "1234", "1234");

    cout << SPKI1 << endl;
    //cout << SPKI2 << endl; cout << SPKI3 << endl; cout << endl; string v1="1.1.1.1";
    string v2="test";
    Attribute Attr1("1.1.1.1", "test", IA5_STRING);
    cout << Attr1 << endl;






    Attribute Attr2("2.2.2.1", {std::make_pair("test", IA5_STRING), {"meow",UTF8_STRING}, {"TEST",PRINTABLE_STRING}});





    Attribute Attr4("1.2.840.113549.1.9.2", "example.com");
    cout << Attr2 << endl;
    cout << Attr4 << endl;


    Attribute Attr3("3.3.3.3", vector<uint8_t>{1,2,3,4,5}, OCTET_STRING);
    cout << Attr3 << endl;
    vector<uint8_t> vec1{1,23};
    vector<uint8_t> vec2{1,4,3,234};
    vector<uint8_t> vec3{2,2,9,0,234,5,31};
    Attribute Attr6("6.6.6.6", vector<pair<vector<uint8_t>,ASN1Tag>>{ {std::move(vec1),OCTET_STRING}, {std::move(vec2),OCTET_STRING}, {std::move(vec3),OCTET_STRING}});
    cout << Attr6 << endl;
    vector<uint8_t> bytes = Attr4.encode();
    print_bytes(bytes);
    SubjectPublicKeyInfo SPKI5(CSRSupportedAlgorithms::rsaEncryption, "1234", "1234");

    CertificationRequestInfo CRI1;
    CertificationRequestInfo CRI2(RDNSequence({{"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"}}), 
                                  SubjectPublicKeyInfo(CSRSupportedAlgorithms::rsaEncryption, "1234567890", "987654321"),
                                  {Attribute("1.2.840.113549.1.1.1", "example.com")});

    CertificationRequestInfo CRI3( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
                                  CSRSupportedAlgorithms::rsaEncryption, std::move(mpz_class("1234567890")), std::move(mpz_class("987654321")),
                                  { {"1.2.840.113549.1.1.1", "example.com"} });
    CertificationRequestInfo CRI4( { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
                                  CSRSupportedAlgorithms::rsaEncryption, "1234567890", "987654321",
                                  { {"1.2.840.113549.1.1.1", "example.com"} });


    CertificationRequest cr1;
    CertificationRequest cr2(
        { {"2.5.4.6","AU"}, {"2.5.4.8", "Some-State"}, {"2.5.4.10", "Internet Widgits Pty Ltd"} },
        CSRSupportedAlgorithms::rsaEncryption,
        std::move("26792313857617382411902256890761250670177401663811189083333481445967123618819533176467585961138397820766519750754971609997534112683553328485637110519877353137905103076021509732281109153670324945828084963211097967269190785781678567970455559651290383123832940892489164014152456849099292897152968779697954284799909266954349340140763576563471343631504029473820686315479506589024985603413799561426101169265121009220329475318594358190579012040572125388805916288457647964629240134491617739754020134147248301391233984516305163654811289202366525593533344277080145951596146824280475639956408129384914004206676822886861605826329"), 
        std::move("65537"),
        {{"1.2.840.113549.1.9.7", "12345"},{"1.2.840.113549.1.9.2", "example.com"}},
        CSRSupportedAlgorithms::sha256WithRSAEncryption
    );

    CertificationRequest cr3(
        { {"2.5.4.6","PL"}, {"2.5.4.8", "Lesser Poland"}, {"2.5.4.10", "AGH"} },
        CSRSupportedAlgorithms::rsaEncryption,
            std::move("26792313857617382411902256890761250670177401663811189083333481445967123618819533176467585961138397820766519750754971609997534112683553328485637110519877353137905103076021509732281109153670324945828084963211097967269190785781678567970455559651290383123832940892489164014152456849099292897152968779697954284799909266954349340140763576563471343631504029473820686315479506589024985603413799561426101169265121009220329475318594358190579012040572125388805916288457647964629240134491617739754020134147248301391233984516305163654811289202366525593533344277080145951596146824280475639956408129384914004206676822886861605826329"), 
        std::move("65537"),
        {},
        CSRSupportedAlgorithms::sha256WithRSAEncryption
    );
    cout << cr2 << endl;
    print_bytes(cr2.encode());
    cout << cr3 << endl;
    print_bytes(cr3.encode());
    // RSAPrivateKey RPK("1", "2", "3", "4", "5", "6", "7", "8");
    // cout<< RPK << endl;
    // PrivateKeyInfo PKI(rsaEncryption, "1", "2", "3", "4", "5", "6", "7", "8");

    // string str1 = "abcd";
    // string str2 = "afcd";
    // cout << PKI << endl;
    // AttributeTypeAndValue test(std::move(str1), std::move(str2));
    // cout << test;
    return 0;
}

