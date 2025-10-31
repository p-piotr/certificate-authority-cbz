#include "encoding.h"

//Note: This function represents length as size_t which is not always safe
//Technically ASN.1/DER allow for of 2^1008-1 bytes that can be used just to indicatelength
//However I don't think we will encounter anything that wouldn't fit in regular int
//It can be changed to use mpz_class if needed

// returns vector that contains all bytes encoding length
static vector<uint8_t> encode_der_length(size_t length){
    // if first length byts i below 0x80 we can just return it
    if (length < 0x80) 
        return { static_cast<uint8_t>(length) } ;

    else {
        // will hold all bytes needed to encode length
        vector<uint8_t> len_bytes;
       
        // we copy length because we will modify it
        size_t temp = length;

        // 0xFF = 11111111
        // we just extract last byte from size and add in into the array
        while (temp > 0){
            len_bytes.push_back(static_cast<uint8_t>((temp & 0xFF)));
            temp >>= 8;
        }


        // we add the to the vector byte that will indicate how many length bytes follow
        // 0x80 + number of bytes
        len_bytes.push_back( (0x80 + static_cast<uint8_t>(len_bytes.size())) );

        // we have to reverse the vector as we inserted last byte first 
        std::reverse(len_bytes.begin(), len_bytes.end());
        return len_bytes;
    }
}


// returns vector that contains all bytes encoding given integer value
vector<uint8_t> encode_der_integer(const mpz_class &value) {
    // 0 is just handled as special case
    // we will always have to encode version = 0
    // so i just decided to handle it separately
    if(value == 0){
        return {0x02, 0x01, 0x00};
    }

    // 0x02 = Integer tag
    vector<uint8_t> integer_bytes = {0x02};

    // Note: before I was doing this manually byte by byte
    // but turns out that Piotrek found better way using mpz_export
    // so I decided to change it

    // How many value bytes we are to encode
    // note that mpz_sizeinbase(mpz_t,2) returns number of bits and it doesn't have to be multiple of 8
    // so I do the trick with adding 7 and then dividing by 8 not to cut any bytes
    size_t bytes_count = (mpz_sizeinbase(value.get_mpz_t(), 2) + 7)/8;

    // vector to hold the integer from mpz_class
    vector<uint8_t> value_bytes(bytes_count);

    // get pointer to first byte in value_bytes
    uint8_t *start = value_bytes.data();
    size_t written;

    // Note: it exports absolute value; so negative numbers will need additional handling
    mpz_export(
        start,              // pointer to array into which we will export
        &written,           // will hold number of words exported by the function
        1,                  // 1=MSB first, -1=LSB first
        sizeof(uint8_t),    // size of each word in bytes
        1,                  // endianness within each word, 1 = big
        0,                  // how many MSB bits of each word should be set zero; not needed here
        value.get_mpz_t()   // mpz_t to copy words from
    );

    // if we have written different number of bytes something must have gone wrong
    if(written != bytes_count)
        throw MyError("encode_der_integer: Wrong Number of bytes written");

    // check if sign is correct
    // our encoding must match 2's complement behaviour
    // i.e. first bit encodes sign 1=- 0=+
     
    // if value is positive but first bit is set it means that
    // the sign must have flipped so we need to append a 0x00 at the start of the value bytes
    if(value > 0 && (value_bytes[0] & 0x80) > 0){
        value_bytes.insert(value_bytes.begin(), 0x00);
    }

    // if number we want to export was negative
    // we need to convert it into 2's complement
    if(value < 0){
        // step 1: invert all bytes
        for(int i = 0; i < value_bytes.size(); i++){
            value_bytes[i] = ~value_bytes[i];
        }

        // step 2: add 1; and don't forget the carry
        // we have to start from the last byte; that's how addition works
        for(int i = value_bytes.size()-1; i >= 0; i--){
            // concise way to add 1 and stop if there's no carry
            if(++value_bytes[i] != 0) break;
        }

        // step 3: check if the sign didn't flip
        if((value_bytes[0] & 0x80) == 0){
            // note that here we have to prepend 0xFF = 11111111 instead of 0x00 here
            value_bytes.insert(value_bytes.begin(), 0xFF);
        }
    }

    // append length bytes 
    vector<uint8_t> integer_length = encode_der_length(value_bytes.size());
    integer_bytes.insert(integer_bytes.end(), integer_length.begin(), integer_length.end());

    // append value bytes 
    integer_bytes.insert(integer_bytes.end(), value_bytes.begin(), value_bytes.end());

    return integer_bytes;
}


// encodes single OID integer (component) e.g. if we have 1.22.33.44 it will be used to just enocde 33 or 44 etc.
static vector<uint8_t> encode_oid_component(uint32_t value) {
    vector<uint8_t> component_bytes;

    // we use do-while so we don't have to handle zero as a special case
    do{
        // 0x7F = 01111111
        // We encode in base 128
        component_bytes.push_back(static_cast<uint8_t>((value & 0x7F)));
        value >>= 7;
    } while (value > 0);

    //we have to invert as we pushed the last 7 bits first
    std::reverse(component_bytes.begin(), component_bytes.end());

    // for all bytes apart from the last one we have to set the MSB
    for (size_t i = 0; i < component_bytes.size() - 1; i++)
        component_bytes[i] |= 0x80;

    return component_bytes;
}


// converts OID string "1.2.3.4.5" into intermediate representation {1, 2, 3, 4, 5}
// stolen from here
// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c
//
// it turns out that getline takes delim as third parameter 
// which can make parsing significantly easier
// https://en.cppreference.com/w/cpp/string/basic_string/getline.html
static vector<uint32_t> string_to_oid(const string &s) {
    char delim = '.';
    vector<uint32_t> result;

    std::stringstream ss (s);
    string item;
    while (getline (ss, item, delim)) {
        result.push_back(static_cast<uint32_t>(stoi(item)));
    }

    return result;
}


// returns OID encoded as bytes
vector<uint8_t> encode_der_oid(const string &oid){
    // get intermediate representation
    vector<uint32_t> inter = string_to_oid(oid);

    // OIDs must have at least 2 components
    if (oid.size() < 2){
        throw std::invalid_argument("OID must have at least two components");
    }

    // 0x06 == OID tag
    vector<uint8_t> oid_bytes = {0x06};   // will store tag + size + value
    vector<uint8_t> value_bytes;          // will store only value


    // encode first 2 components as 40 * X + Y
    vector<uint8_t> firsttwo = encode_oid_component(inter[0] * 40 + inter[1]);
    value_bytes.insert(value_bytes.end(), firsttwo.begin(), firsttwo.end());


    // we encode  number by number and append bytes to value_bytes
    for (size_t i = 2; i < inter.size(); i++){
        vector<uint8_t> component_bytes = encode_oid_component(inter[i]);
        value_bytes.insert(value_bytes.end(), component_bytes.begin(), component_bytes.end());
    }

    // encode length of the value bytes and append to result
    vector<uint8_t> length_bytes = encode_der_length(value_bytes.size());
    oid_bytes.insert(oid_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append value bytes to result
    oid_bytes.insert(oid_bytes.end(), value_bytes.begin(), value_bytes.end());

    return oid_bytes;
}



// test if string doesn't contain illegal characters; printable_string version
static bool printable_string_validate(const string &s){
    // set of all legal chars in PRINTABLE_STRING
    const std::unordered_set<char> legal = {
        'A', 'a', 'B', 'b', 'C', 'c', 'D', 'd', 'E', 'e',
        'F', 'f', 'G', 'g', 'H', 'h', 'I', 'i', 'J', 'j',
        'K', 'k', 'L', 'l', 'M', 'm', 'N', 'n', 'O', 'o',
        'P', 'p', 'Q', 'q', 'R', 'r', 'S', 's', 'T', 't',
        'U', 'u', 'V', 'v', 'W', 'w', 'X', 'x', 'Y', 'y',
        '0', '1', '2', '3', '4', '5', '6', '7', '8',
        ' ', '\'', '(', ')', '+', ',', '-', '.', '/',
        ':', '?', '='
    };

    // returns false if string contains char not found in set of legal chars
    for (char c : s) {
        if (legal.find(c) == legal.end()) {
            return false; 
        }
    }
    return true;
}


// test if string doesn't contain illegal characters ia5string version
static bool ia5string_validate(const string &s){
    // returns false if string contains a char not found in set of legal chars
    for (unsigned char c : s) {
        if (c > 0x7F) return false;  // Only first 128 ASCII chars allowed
    }
    return true;
}

vector<uint8_t> encode_der_string(const string &str, string_t str_type){
    vector<uint8_t> string_bytes;       // will store tag + size + value
    
    switch(str_type){
        case IA5STRING:
            if(ia5string_validate(str) == false){
                throw MyError("encode_der_string: Attempt to encode illegal chars in ia5string type");
            }
            // 0x16 = ia5string tag
            string_bytes.push_back(0x16);
            break;

        case PRINTABLE_STRING:
            if(printable_string_validate(str) == false){
                throw MyError("encode_der_string: Attempt to encode illegal chars in printable_string type");
            }
            // 0x13 = printable_string tag
            string_bytes.push_back(0x13);
            break;

        case UTF8_STRING:
            // 0x0C = utf8_string tag
            // Note: I assume that UTF8 can handle every character
            string_bytes.push_back(0x0C);
            break;
    }

    // initialize the value_bytes vector with string bytes already
    vector<uint8_t> value_bytes(str.begin(), str.end());     // will store only value

    // append length bytes
    vector<uint8_t> length_bytes = encode_der_length(value_bytes.size());
    string_bytes.insert(string_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append value bytes
    string_bytes.insert(string_bytes.end(), value_bytes.begin(), value_bytes.end());

    return string_bytes;
}


// This is far for perfect but I haven't come up with more straightforward solution
// it simply takes vector of vectors  each containing value bytes and concatenates them
// it of course also adds length and tag bytes
vector<uint8_t> encode_der_sequence(const vector<vector<uint8_t>> &elements){
    // append elements bytes one by one
    vector<uint8_t> value_bytes;
    for (auto &element : elements){
        value_bytes.insert(value_bytes.end(), element.begin(), element.end());
    }

    // 0x30 = sequence tag
    vector<uint8_t> sequence_bytes = {0x30};

    //append length bytes
    vector<uint8_t> length_bytes = encode_der_length(value_bytes.size());
    sequence_bytes.insert(sequence_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append value bytes
    sequence_bytes.insert(sequence_bytes.end(), value_bytes.begin(), value_bytes.end());
    return sequence_bytes;
}


// similar to encode_der_sequence but it sorts the elements first as required by DER
// also adds a different tag 
vector<uint8_t> encode_der_set(vector<vector<uint8_t>> &elements){
    // I decided to sort the orignal not the copy
    // most of the time you will have to copy elements
    // into a new vector before calling the function anyway
    std::sort(elements.begin(), elements.end());

    // append elements bytes one by one
    vector<uint8_t> value_bytes;
    for (auto &element : elements){
        value_bytes.insert(value_bytes.end(), element.begin(), element.end());
    }

    // 0x31 = set tag
    vector<uint8_t> set_bytes = {0x31};

    // append length bytes
    vector<uint8_t> length_bytes = encode_der_length(value_bytes.size());
    set_bytes.insert(set_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append value bytes
    set_bytes.insert(set_bytes.end(), value_bytes.begin(), value_bytes.end());
    return set_bytes;
}

// this function is also quite similar to the two above it but it appends the number of unused bytes
vector<uint8_t> encode_der_bitstring(const vector<uint8_t>& bits, uint8_t unused) {
    // in bitstring first value byte encodes how many bits are not used 
    // (e.g. if you want to encode 18 bits you have to round it up to 3 bytes so 6 bits will be unused)

    // if you have more than 7 unused bits you don't even encode the unused bytes
    if(unused > 7)
        throw MyError("encode_der_bitstring: bit string can't have more than 7 unused bits");


    // 0x03 = bitstring tag
    vector<uint8_t> bitstring_bytes = {0x03};

    // append length bytes
    // note the +1; it corresponds to unused_bits byte
    vector<uint8_t> length_bytes = encode_der_length(bits.size() + 1);
    bitstring_bytes.insert(bitstring_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append value bytes
    // note that unused_bits bytes is added first
    bitstring_bytes.push_back(unused);
    bitstring_bytes.insert(bitstring_bytes.end(), bits.begin(), bits.end());
    return bitstring_bytes;

}

// another quite similar function
vector<uint8_t> encode_der_octet_string(const vector<uint8_t> &bytes){
    // 0x04 = octet string tag
    vector<uint8_t> octet_string_bytes = {0x04};

    // append length bytes
    vector<uint8_t> length_bytes = encode_der_length(bytes.size());
    octet_string_bytes.insert(octet_string_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append input bytes
    octet_string_bytes.insert(octet_string_bytes.end(), bytes.begin(), bytes.end());

    return octet_string_bytes;
}

// I don't like the existance of this function but PKCS force my hand
vector<uint8_t> encode_der_non_universal(const vector<uint8_t> &bytes, uint8_t tag){
    vector<uint8_t> non_universal_bytes = {tag};

    // append length bytes
    vector<uint8_t> length_bytes = encode_der_length(bytes.size());
    non_universal_bytes.insert(non_universal_bytes.end(), length_bytes.begin(), length_bytes.end());

    // append input bytes
    non_universal_bytes.insert(non_universal_bytes.end(), bytes.begin(), bytes.end());

    return non_universal_bytes;
}


// https://gist.github.com/williamdes/308b95ac9ef1ee89ae0143529c361d37
// note that this function is whitespace-sensitive
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

