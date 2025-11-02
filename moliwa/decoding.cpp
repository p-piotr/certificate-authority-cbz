#include "decoding.h"

// returns length of the ASN.1/DER object
static size_t decode_der_length(const vector<uint8_t> &der_buffer, size_t &offset){
    size_t length = 0;

    // if length is less than 0x80 just return it
    if(der_buffer[offset] < 0x80)
        return der_buffer[offset++];

    // Length cannot be equal to 0x80 in DER encoding 
    if(der_buffer[offset] == 0x80)
        throw MyError("decode_der_buffer_length: does not support indefinite length encoding" );

    else{
        // 0x7F == 01111111
        // we extract last 7 bits to see how many bytes should follow
        int length_bytes_count = (der_buffer[offset++] & 0x7F);

        // check if we won't go out of bands
        if (offset + length_bytes_count >= der_buffer.size())
            throw MyError("decode_der_buffer_length: der_buffer is to small to hold all length bytes");

        // we iterate through next length_bytes_count bytes and save it into the length vaiable
        // we need to save the first byte index in order to know when to stop
        for(int i = 0; i < length_bytes_count; i++){
            length <<= 8;
            length |= der_buffer[offset++];
        }
    }

    // check if the buffer matches the decoded length
    if(offset + length > der_buffer.size())
        throw MyError("decode_der_buffer_length: der_buffer is smaller than the decoded length");

    return length;
}


// returns decoded integer as mpz_class object
mpz_class decode_der_integer(const vector<uint8_t> &der_buffer, size_t &offset){

    // check if tag byte is correct
    if(der_buffer[offset++] != 0x02){
        throw MyError("decode_der_integer: value " + std::to_string(der_buffer[offset-1]) + " does not correspond to INTEGER tag");
    }


    // use decode_der_length function to decode length
    size_t int_length;
    try {
        int_length = decode_der_length(der_buffer, offset);
    } catch (const MyError &e) {
        std::throw_with_nested(MyError("decode_der_integer: failed to decode length"));
    }

    // check if the first bit is set to determine if the number is negative
    bool negative = ((der_buffer[offset] & 0x80) > 0);

    // Note: before I was doing this manually byte by byte
    // but turns out that Piotrek found better way using mpz_import
    // so I decided to change it
    mpz_class value;
    const uint8_t *start = der_buffer.data() + offset;

    //note that this will import it as unsigned int
    mpz_import(
        value.get_mpz_t(),  // mpz_class into which data will be imported
        int_length,         // number of words to import
        1,                  // 1=MSB first, -1=LSB first
        sizeof(uint8_t),    // size of each word in bytes
        1,                  // endianness within each word, 1 = big
        0,                  // how many MSB bits of each word should be set zero
        start               // pointer to array read words from
    );

    // using the following formula for 2's complement
    // v_signed = v_unsigned - 2^N
    // where N is the number of bits
    if(negative){
        // int_length * 8 is equal to the number of bits
        mpz_class subtrahend = mpz_class(1) << (int_length * 8);

        #ifdef DEBUG
        std::cout << "decode_der_integer: int_length=" << int_length << std::endl;
        std::cout << "decode_der_integer: subtrahend=" << subtrahend << std::endl;
        #endif

        value -= subtrahend;
    }

    offset += int_length;
    return value;
}

// decodes and returns one integer (component) of OID e.g. if we have 1.22.33.44 it will be used to just deocode 33 or 44 etc.
// component can be encoded using multiple bytes
static uint32_t decode_oid_component(const vector<uint8_t> &der_buffer, size_t &offset) {
    uint32_t component = 0;
    for(;;){
        // components are encoded in base 128
        // 0x7F = 01111111
        component <<= 7;
        component |= (der_buffer[offset] & 0x7F);

        // if first bit is set it means this was the last byte of that component
        // 0x80 = 10000000
        if((der_buffer[offset++] & 0x80) == 0){
            break;
        }
    }
    return component;
}

// converts OID from intermediate represenation to string e.g. {1, 5, 8, 20} --> "1.5.8.20"
// stolen from:
// https://stackoverflow.com/questions/6097927/is-there-a-way-to-implement-analog-of-pythons-separator-join-in-c
// it's stolen so hard it could even be used for different purpose completely as it uses template
template <typename Iter>
static string oid_to_string(Iter begin, Iter end, string const &sep){
    std::ostringstream result;
    if (begin != end)
        result << *begin++;
    while(begin != end)
        result << sep << *begin++;
    return result.str();
}

// returns string representing OID i.e. "1.2.3.4.5" decoded from bytes
string decode_der_oid(const vector<uint8_t> &der_buffer, size_t &offset){
    // check if tag byte is correct
    if(der_buffer[offset++] != 0x06){
        throw MyError("decode_der_oid: value " + std::to_string(der_buffer[offset-1]) + " does not correspond to OID tag");
    }

    // decode OID length
    size_t oid_length;
    try {
        oid_length = decode_der_length(der_buffer, offset);
    } catch (const MyError &e) {
        std::throw_with_nested(MyError("decode_der_oid: failed to decode length"));
    }

    // save where OID bytes start to know when to stop
    size_t start = offset;

    // intermediate representation storing just integer values i.e. {1, 2, 3, 4, 5}
    vector<uint32_t> inter;

    // first 2 components
    // Note: it was previously done incorrectly, now it's pretty much identical as Piotrek's
    uint32_t firsttwo = decode_oid_component(der_buffer, offset);

    if(firsttwo < 40){
        inter.push_back(0);
        inter.push_back(firsttwo);
    }
    else if (firsttwo < 80) {
        inter.push_back(1);
        inter.push_back(firsttwo - 40);
    } 
    else {
        inter.push_back(2);
        inter.push_back(firsttwo - 80);
    }


    // convert number by number
    while(offset < start + oid_length)
        inter.push_back(decode_oid_component(der_buffer, offset));

    // convert intermediate represenation to string
    return oid_to_string(inter.begin(), inter.end(), ".");
}

// returns size in bytes of the sequence
size_t decode_der_sequence(const vector<uint8_t> &der_buffer, size_t &start){
    // check if tag is correct
    if(der_buffer[start++] != 0x30){
        throw MyError("decode_der_sequence: value " + std::to_string(der_buffer[start-1]) + " does not correspond to SEQUENCE tag");
    }

    // try decoding length
    size_t seq_length;
    try {
        seq_length = decode_der_length(der_buffer, start);
    } catch (const MyError &e) {
        std::throw_with_nested(MyError("decode_der_sequence: failed to decode length"));
    }

    return seq_length;
}


// returns size in bytes of the octet_string
size_t decode_der_octet_string(const vector<uint8_t> &der_buffer, size_t &start){
    // check if tag is correct
    if(der_buffer[start++] != 0x04){
        throw MyError("decode_der_octet_string: value " + std::to_string(der_buffer[start-1]) + " does not correspond to OCTET STRING tag");
    }

    // try decoding length
    size_t oct_length;
    try {
        oct_length = decode_der_length(der_buffer, start);
    } catch (const MyError &e) {
        std::throw_with_nested(MyError("decode_der_octet_string: failed to decode length"));
    }

    return oct_length;
}


// Just base64 decoding stolen from:
// https://gist.github.com/williamdes/308b95ac9ef1ee89ae0143529c361d37
// I decided to change this function to take reference to the out vector
// I don't want to leave some not zeroized buffers
void base64_decode(const string &in, vector<uint8_t> &out){
    static const string b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    vector<int> T(256,-1);
    for (int i=0; i<64; i++) T[b64_chars[i]] = i;

    int val=0, valb=-8;
    for (uint8_t c : in) {
        if (T[c] == -1) {
            throw MyError("base64_decode: input string contains illegal chars");
        }
        val = (val<<6) + T[c];
        valb += 6;
        if (valb>=0) {
            out.push_back(((val>>valb)&0xFF));
            valb-=8;
        }
    }
}
