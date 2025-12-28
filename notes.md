1. These functions may leave some traces in memory
``` C++
RSAPrivateKey RSAPrivateKey::from_file(std::string const& filepath)
RSAPrivateKey RSAPrivateKey::from_file(std::string const& filepath, std::string&& passphrase)
```
- They don't zeroize the base64 buffer
- ifstream internal buffers are out of our control and we can't zeroize them at all.




2. I don't like this snippet fragment from
`std::string ASN1Parser::object_identifier_decode(std::vector<uint8_t> const& data)`

```C++
while (re != data.crend()) {
    if (*re  & 0x80) { // MSB set - continue
        re++;
        continue;
    }
    // decode single integer and prepend it to the result string
    integer_str = _ASN1ObjectIdentifier_decode_single_integer(rb, re).get_str();
    result.insert(result.cbegin(), integer_str.begin(), integer_str.end());
    result.insert(result.cbegin(), '.');
    rb = re;
    re = rb + 1;
}
```
- It must copy the part that already exists in the `result` string each time new `integer_str` is inserted.
- It would be better to construct the string from behind and then reverse it - avoiding repeated copies.
- Same goes for appending first 2 string they also cause extra copies.
- It's already done in reverse so it should be quite easy to change it.


3. This functions won't work for negative numbers:
```c++
std::vector<uint8_t> ASN1Parser::integer_encode(mpz_class const& num)
mpz_class ASN1Parser::integer_decode(std::vector<uint8_t> const& data)
```
- It's not like we intend to use negative numbers but it's something to keep in mind.



4. In what format do we assume `s` vector to be?
```c++
ASN0BitString::ASN1BitString(std::vector<uint8_t> s, int unused)
    : ASN1Object(BIT_STRING, std::move(s))
{
    if (unused > 7)
        throw std::runtime_error("[ASN1BitString::ASN1BitString] cannot exceed 7 unused bits");

    _value.insert(_value.cbegin(), static_cast<uint8_t>(unused));
    _length += 1;
}
```
- Is the last byte assumed to already match with the number of unused bits or should we handle this here?



5. Won't calling this functions repeatedly cause the decoding to repeat?
``` c++
inline std::string const value() const {
    return ASN1Parser::object_identifier_decode(_value);
}

inline mpz_class const value() const {
    return ASN1Parser::integer_decode(_value);
}
```
- Shouldn't there be an additional member that will store the decoded value after the first call to decode()?

6. Why define it hmac.hpp?
```C++
template <typename _PRF>
concept PseudoRandomFunction = requires(
    std::span<uint8_t const> m,
    std::span<uint8_t const> k,
    uint8_t* od
) {
    { _PRF::KEY_SIZE } -> std::convertible_to<size_t>;
    { _PRF::DIGEST_SIZE } -> std::convertible_to<size_t>;

    { _PRF::digest(m, k, od) } -> std::same_as<void>;
};
```
- This snippet is defined in hmac.hpp even though it's not used there at all?
- Isn't it better to define it in kdf.hpp?

7. I don't understand this snippet
```C++
auto pbes2_parameters = out_ptr ? 
    std::make_shared<PBES2::Parameters>() : std::shared_ptr<PBES2::Parameters>(nullptr);
```
What is the difference between empty shared_ptr and shared_ptr with nullptr?
And why should we care about this difference?



