#include "encoding.h"
#include <sstream>

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

vector<uint8_t> encode_der_integer(const mpz_class &value) {
    vector<uint8_t> bytes;

    if(value == 0){
        return {0x02, 0x01, 0x00};
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

    
    vector<uint8_t> der = {0x02};
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

vector<uint8_t> encode_der_oid(const vector<uint32_t> &oid){
    if (oid.size() < 2){
        throw std::invalid_argument("OID must have at least two components");
    }

    vector<uint8_t> oid_enc;
    oid_enc.push_back(static_cast<uint8_t>(oid[0] * 40 + oid[1]));
    for (size_t i = 2; i < oid.size(); i++){
        vector<uint8_t> enc = encode_oid_component(oid[i]);
        oid_enc.insert(oid_enc.end(), enc.begin(), enc.end());
    }

    vector<uint8_t> der = {0x06};
    vector<uint8_t> length = encode_der_length(oid_enc.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), oid_enc.begin(), oid_enc.end());

    return der;
}


vector<uint8_t> encode_der_string(const string &str, string_t str_type){
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
    vector<uint8_t> der = {tag};
    vector<uint8_t> length = encode_der_length(bytes.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), bytes.begin(), bytes.end());
    return der;
}

//https://gist.github.com/mattearly/d8afe122912eb8872bc0fddb62a32376
vector<uint32_t> split_oid(const string &oid){
    vector<uint32_t> elements;
    std::stringstream ss;
    ss.str(oid);
    string item;
    uint32_t element;
    while(std::getline(ss, item, '.')){
        element = static_cast<uint32_t>(std::stoi(item));
        elements.push_back(element);
    }
    return elements;
}

string serialize_oid(const vector<uint32_t> &oid){
    string serial = "";
    for(auto val : oid)
        serial += std::to_string(val) + '.';
    serial.pop_back();
    return serial;
}


vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>> &elements){
    vector<uint8_t> content;
    for (auto& el : elements){
        content.insert(content.end(), el.begin(), el.end());
    }
    vector<uint8_t> der = {0x30};
    vector<uint8_t> length = encode_der_length(content.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), content.begin(), content.end());
    return der;
}

vector<uint8_t> encode_der_set(const vector<vector<uint8_t>> &elements){
    vector<vector<uint8_t>> sorted = elements;
    std::sort(sorted.begin(), sorted.end());

    vector<uint8_t> content;
    for(const auto &el : sorted)
        content.insert(content.end(), el.begin(), el.end());

    vector<uint8_t> der = {0x31};
    vector<uint8_t> length = encode_der_length(content.size());
    der.insert(der.end(), length.begin(), length.end());
    der.insert(der.end(), content.begin(), content.end());
    return der;
}

vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bytes) {
    vector<uint8_t> out = {0x03};

    vector<uint8_t> content = {0x00}; // 0 unused bits
    content.insert(content.end(), bytes.begin(), bytes.end());

    vector<uint8_t> len = encode_der_length(content.size());
    out.insert(out.end(), len.begin(), len.end());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

// https://gist.github.com/williamdes/308b95ac9ef1ee89ae0143529c361d37
string base64_encode(const vector<uint8_t> &in) {
    static const string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    string out;
    int val = 0, valb = -6;

    for (uint8_t c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(b64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        out.push_back(b64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (out.size() % 4) {
        out.push_back('=');
    }

    return out;
}
