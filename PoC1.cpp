#include <iostream>
#include <bitset>
#include <sstream>
#include <cinttypes>
#include <vector>
#include <gmpxx.h>

using std::string;
using std::vector;
using std::cout;
using std::endl;

static vector<uint8_t> der_null = {0x05, 0x00};


vector<uint8_t> encode_der_length(size_t length){
    vector<uint8_t> out;
    if (length < 0x80) {
        out.push_back(static_cast<uint8_t>(length));
        return out;
    }
    else {
        vector<uint8_t> len_bytes;
        size_t temp = length;
        while (temp > 0){
            len_bytes.insert(len_bytes.begin(), static_cast<uint8_t>((temp & 0xFF)));
            temp >>= 8;
        }

        uint8_t prefix = (0x80 | static_cast<uint8_t>(len_bytes.size()));
        out.push_back(prefix);
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
    }
    return out;
}

vector<uint8_t> encode_der_integer(mpz_class value) {
    vector<uint8_t> bytes;

    if(value == 0){
        return {0x02, 0x10, 0x00};
    }

    bool negative = (value < 0);
    mpz_class abs_value = negative ? -value : value;

    while(abs_value > 0) {
        mpz_class mpzbyte = (abs_value & 0xFF);
        uint8_t byte = mpzbyte.get_ui();
        bytes.insert(bytes.begin(), byte);
        abs_value >>= 8;
    }

    if(negative){
        // two's complement
        for(auto &b : bytes)
            b = ~b;
        for(int i = bytes.size() - 1; i >= 0; i--){
            if(++bytes[i] != 0) break;
        }

        if((bytes[0] & 0x80) == 0)
            bytes.insert(bytes.begin(), 0xFF);
    }
    else{
        while(bytes.size() > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0)
            bytes.erase(bytes.begin());
        if(bytes[0] & 0x80)
            bytes.insert(bytes.begin(), 0x00);
    }

    
    vector<uint8_t> der;
    der.push_back(0x02);
    vector<uint8_t> length = encode_der_length(bytes.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), bytes.begin(), bytes.end());

    return der;
}

static vector<uint8_t> encode_oid_component(uint32_t value) {
    vector<uint8_t> encoding;
    do{
        encoding.insert(encoding.begin(), static_cast<uint8_t>((value & 0x7F)));
        value >>= 7;
    } while (value > 0);

    for (size_t i = 0; i < encoding.size() - 1; i++)
        encoding[i] |= 0x80;

    return encoding;
}

vector<uint8_t> encode_der_oid(const vector<uint32_t>& oid){
    if (oid.size() < 2){
        throw std::invalid_argument("OID must have at least two components");
    }

    vector<uint8_t> oid_enc;
    oid_enc.push_back(static_cast<uint8_t>(oid[0] * 40 + oid[1]));
    for (size_t i = 2; i < oid.size(); i++){
        vector<uint8_t> enc = encode_oid_component(oid[i]);
        oid_enc.insert(oid_enc.end(), enc.begin(), enc.end());
    }

    vector<uint8_t> der;
    der.push_back(0x06);
    vector<uint8_t> length = encode_der_length(oid_enc.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), oid_enc.begin(), oid_enc.end());

    return der;
}

enum string_t{
    IA5STRING,
    PRINTABLE_STRING,
    UTF8_STRING
};

vector<uint8_t> encode_der_string(string str, string_t str_type){
    vector<uint8_t> bytes(str.begin(), str.end());
    uint8_t tag;
    switch(str_type){
        case IA5STRING:
            tag = 0x16;
            break;
        case PRINTABLE_STRING:
            tag = 0x13;
            break;
        case UTF8_STRING:
            tag = 0x0C;
            break;
    }
    vector<uint8_t> der;
    der.push_back(tag);
    der.push_back(bytes.size());
    der.insert(der.end(), bytes.begin(), bytes.end());
    return der;
}

class AttribiuteTypeAndValue{
    vector<uint32_t> oid;
    string value;
    string_t value_type;

    AttribiuteTypeAndValue(){

    }
};

vector<uint32_t> split_oid(string oid){
    //https://gist.github.com/mattearly/d8afe122912eb8872bc0fddb62a32376
    vector<uint32_t> elements;
    std::stringstream ss;
    ss.str(oid);
    string item;
    uint32_t element;
    while(std::getline(ss, item, '.')){
        element = static_cast<uint32_t>(std::stoi(item));
        elements.push_back(element);
    }
    cout << endl;
    return elements;
}



int main(){
    vector<uint8_t> bytes;

    bytes = encode_der_string("hi", PRINTABLE_STRING);
    for(auto byte : bytes)
        printf("%.2X ", byte);
    cout << endl;

    bytes = encode_der_string("hi", IA5STRING);
    for(auto byte : bytes)
        printf("%.2X ", byte);
    cout << endl;
    
    bytes = encode_der_string("😎", PRINTABLE_STRING);
    for(auto byte : bytes)
        printf("%.2X ", byte);
    cout << endl;

    return 0;
}
