#ifndef map_header
#define map_header

#include <map>
#include <string>
#include <vector>
#include <cinttypes>

using std::string;
using std::vector;
using std::map;

enum string_t{
    IA5STRING,
    PRINTABLE_STRING,
    UTF8_STRING
};

static const vector<uint8_t> der_null = {0x05, 0x00};

static const map<string, vector<uint32_t>> AttributesToOIDs = {
    {"countryName",              {2, 5, 4, 6}},
    {"stateOrProvinceName",      {2, 5, 4, 8}},
    {"localityName",             {2, 5, 4, 7}},
    {"organizationName",         {2, 5, 4, 10}},
    {"organizationalUnitName",   {2, 5, 4, 11}},
    {"commonName",               {2, 5, 4, 3}},
    {"emailAddress",             {1, 2, 840, 113549, 1, 9, 1}},
    {"unstructuredName",         {1, 2, 840, 113549, 1, 9, 2}},
    {"challengePassword",        {1, 2, 840, 113549, 1, 9, 7}},
    {"rsaEncryption",            {1, 2, 840, 113549, 1, 1, 1}},
    {"sha256WithRSAEncryption",  {1, 2, 840, 113549, 1, 1, 11}},
};


static const map<string, string> OIDsToAttributes = {
    {"2.5.4.6",                "countryName"},
    {"2.5.4.8",                "stateOrProvinceName"},
    {"2.5.4.7",                "localityName"},
    {"2.5.4.10",               "organizationName"},
    {"2.5.4.11",               "organizationalUnitName"},
    {"2.5.4.3",                "commonName"},
    {"1.2.840.113549.1.9.1",   "emailAddress"},
    {"1.2.840.113549.1.9.2",   "unstructuredName"},
    {"1.2.840.113549.1.9.7",   "challengePassword"}, 
    {"1.2.840.113549.1.1.1",   "rsaEncryption"}, 
    {"1.2.840.113549.1.1.11",  "sha256WithRSAEncryption"},
};

static const map<string, string_t> AttributeStringTypes = {
    {"2.5.4.6",                PRINTABLE_STRING},   // countryName
    {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
    {"2.5.4.7",                UTF8_STRING},        // localityName
    {"2.5.4.10",               UTF8_STRING},        // organizationName
    {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
    {"2.5.4.3",                UTF8_STRING},        // commonName
    {"1.2.840.113549.1.9.1",   IA5STRING},          // emailAddress
    {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
    {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
};

#endif
