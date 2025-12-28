#include <string>
#include <cstdint>
#include <vector>
#include <memory>
#include <stdexcept>
#include <span>
#include <variant>
#include <utility>
#include "pkcs/pkcs.h"
#include "pkcs/csr.h"
#include "pkcs/public_key.h"
#include "pkcs/sign.h"
#include "asn1/asn1.h"
#include "encryption/kdf.hpp"
#include "encryption/aes.h"
#include "utils/utils.hpp"

namespace CBZ::PKCS {

    const std::unordered_map<std::string, ASN1Tag> attributeStringTypeMap = {
        {"2.5.4.6",                PRINTABLE_STRING},   // countryName
        {"2.5.4.8",                UTF8_STRING},        // stateOrProvinceName
        {"2.5.4.7",                UTF8_STRING},        // localityName
        {"2.5.4.10",               UTF8_STRING},        // organizationName
        {"2.5.4.11",               UTF8_STRING},        // organizationalUnitName
        {"2.5.4.3",                UTF8_STRING},        // commonName
        {"1.2.840.113549.1.9.1",   IA5_STRING },        // emailAddress
        {"1.2.840.113549.1.9.2",   UTF8_STRING},        // unstructuredName
        {"1.2.840.113549.1.9.7",   UTF8_STRING}         // challengePassword
    };

    ASN1Object AlgorithmIdentifier::to_asn1() const {
        auto find = CSRSupportedAlgorithms::algorithmMap.find(algorithm);
        if (find == CSRSupportedAlgorithms::algorithmMap.end())
            throw std::runtime_error("[AlgorithmIdentifier::encode] Unsupported algorithm");

        return ASN1Sequence({
            ASN1ObjectIdentifier(find->second),
            ASN1Null()
        });
    }

    std::vector<uint8_t> AlgorithmIdentifier::encode() const {
        return this->to_asn1().encode();
    }

    // Example: AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters:?}
    // I removed the parameters handling since their structure is dependent on the algorithm itself and there's no use in going into this rabbit hole
    std::ostream& operator<<(std::ostream& os, const PKCS::AlgorithmIdentifier& ai) {
        os  << "AlgorithmIdentifier = {algorithm: "
            << ai.algorithm
            << ", parameters:?} ";
        return os;
    }

    Attribute::Attribute(
        std::string type,
        std::string value,
        ASN1Tag tag
    ) : _type(std::move(type)) {
        if(tag != UTF8_STRING && tag != IA5_STRING && tag != PRINTABLE_STRING){
            throw std::runtime_error("[Attribute::Attribute(std::string, std::string, ASN1Tag)] Tag doesn't match the string type");
        }
        if(CBZ::Utils::validate_string_type(value, tag) == false){
            throw std::runtime_error("[Attribute::Attribute(std::string, std::string, ASN1Tag)] attempt to create object with value that contains illegal characters");
        }
        _values.emplace_back(std::move(value), tag);
    }

    Attribute::Attribute(
        std::string type,
        std::string value
    ) {
        ASN1Tag tag;
        try {
            tag = attributeStringTypeMap.at(type);
            if(CBZ::Utils::validate_string_type(value, tag) == false){
                throw std::runtime_error("[Attribute::Attribute(std::string, std::string)] value_ contains illegal chars");
            }
        } catch (const std::out_of_range& e) { 
            tag = UTF8_STRING;
        }
        _type = std::move(type);
        _values.emplace_back(std::move(value), tag);
    }

    Attribute::Attribute(
        std::string type,
        std::initializer_list<std::pair<std::string, ASN1Tag>> list
    ) : _type(std::move(type)) {
        _values.reserve(list.size());
        for (auto& v : list){
            if(v.second != UTF8_STRING && v.second != IA5_STRING && v.second != PRINTABLE_STRING){
                throw std::runtime_error("[Attribute::Attribute(std::string, std::initializer_list<std::pair<std::string, ASN1Tag>>)] Tag doesn't match string type");
            }
            if(CBZ::Utils::validate_string_type(v.first,v.second) == false){
                throw std::runtime_error("[Attribute::Attribute(std::string, std::initializer_list<std::pair<std::string, ASN1Tag>>)] Attempt to create object with value that contains illegal characters");
            }
            _values.emplace_back(std::move(v.first), v.second);
        }
    }

    Attribute::Attribute(
        std::string type,
        std::initializer_list<std::string> list
    ) : _type(std::move(type)) {
        _values.reserve(list.size());
        for (auto& v : list){
            ASN1Tag tag;
            try {
                tag = attributeStringTypeMap.at(type);
                if(CBZ::Utils::validate_string_type(v, tag) == false){
                    throw std::runtime_error("[Attribute::Attribute(std::string, std::initializer_list<std::string>)] Attempt to create object with value that contains illegal characters");
                }
            } catch (const std::out_of_range& e) { 
                tag = UTF8_STRING;
            }
            _values.emplace_back(std::move(v), tag);
        }
    }

    Attribute::Attribute(
        std::string type,
        std::vector<uint8_t> value,
        ASN1Tag tag
    ) : _type(std::move(type)) {
        _values.emplace_back(std::move(value), tag);
    }

    Attribute::Attribute(
        std::string type,
        std::vector<std::pair<std::vector<uint8_t>, ASN1Tag>> list
    ) : _type(std::move(type)) {
        for (auto& v : list){
            _values.emplace_back(std::move(v.first), v.second);
        }
    }

    ASN1Object Attribute::to_asn1() const {
        std::vector<ASN1Object> components;

        for (const auto& element : _values) {
            const variant_object& val = element.first;
            ASN1Tag tag = element.second;

            switch (tag) {
                case PRINTABLE_STRING:
                case IA5_STRING:
                case UTF8_STRING:
                    components.push_back(
                        ASN1String(tag, std::get<std::string>(val))
                    );
                    break;
                case OCTET_STRING:
                    components.push_back(
                        ASN1OctetString(std::get<std::vector<uint8_t>>(val))
                    );
                    break;
                default:
                    throw std::runtime_error("[Attribute::to_asn1] given tag does not match any string type");
            }
        }

        return ASN1Sequence({
            ASN1ObjectIdentifier(_type),
            ASN1Set(std::move(components))
        });
    }

    std::vector<uint8_t> Attribute::encode() const {
        return this->to_asn1().encode();
    }

    // Example: Attribute = { Type: 2.2.2.1, values = [ (tag: 22 "test"), (tag: 12 "meow"), (tag: 19 "TEST") ] }
    std::ostream& operator<<(std::ostream& os, const PKCS::Attribute& ATTR){
        using variant_object = 
        std::variant<
        std::string,
        std::vector<uint8_t> 
        >;

        os  << "Attribute = {"
            << " Type: "
            << ATTR._type
            << ", values = [ ";

        bool first = true; 
        // used in second method of avoding dangling commas
    
        // iterate thorugh the vector of pairs
        // adding each value to the stream
        for(const auto& PAIR : ATTR._values){
            // first values is is the varaiant second the tag
            const variant_object& val = PAIR.first;
            const ASN1Tag& tag = PAIR.second;

            // dangling commas avoidance
            if(!first) { os << ", "; }
            first = false;

            os << "(tag: " << tag << " ";

            // Detailed explaination of the std::visit code:
            //
            // std::visit([&tag,& val,& os](auto &&arg) { ... }, val);
            // "visit takes a variant and a set of functions, and calls the correct function based on the type the variant is holding at the time."
            // https://www.reddit.com/r/cpp_questions/comments/12ur4wv/what_exactly_are_stdvisit_and_stdvariant/
            //
            // It is usually done with lambda function as we don't want to name the function
            // in lambda:
            // [] = which values from local scope we should allow lambda to access
            // () = parameters
            // {} = body
            // val = variant - second argument to the std::visit function
            // auto&& arg = will know if arg is lvalue or rvalue and will deduce type based on that
            // https://stackoverflow.com/questions/13230480/what-is-the-meaning-of-a-variable-with-type-auto
            //
            // using T = std::decay_t<decltype(arg)>; 
            // decltype(arg) - detects type of arg at compile-time
            // std::decay_t - removes qualifiers and references such as const or &&
            // It's done because we will compare type of arg to some type like std::string
            // we want this compare to also work for const& string etc. so we just strip those
            //
            // if constexpr (std::is_same_v<T, std::string>) { ... }
            // if constexpr - we want to compare times at compile-time and constexpr will be evaluated at compile-time if used in a constant expression
            // std::is_same<T, U>::value = a class that compares type of T and U; and stores the result into value member 
            // note that std::is_same_v<T, U> can also be used
            //
            std::visit([&val,& os,& first](auto&& arg) { 
                // this is just used for convinence 
                using T = std::decay_t<decltype(arg)>; 

                // string
                if constexpr (std::is_same<T, std::string>::value) {
                    os << "\"" << arg << "\"";
                } 
                // byte vector
                else if constexpr (std::is_same<T, std::vector<uint8_t>>::value){
                    os << "bytes[ " << std::hex << std::setfill('0');
                    // print each byte
                    for(uint8_t byte : arg){
                        os << " 0x" << std::setw(2) << std::setfill ('0') << static_cast<int>(byte);
                    }

                    os << std::dec << " ]";
                }
            }, val);
            os << ")";
        }
        os << " ] } ";
        return os;
    }

    ASN1Object SubjectPublicKeyInfo::to_asn1() const {
        return ASN1Sequence({
            _algorithm.to_asn1(), // here's the MaksymilianOliwa legacy code
            _subject_public_key.to_asn1()
        });
    }

    std::vector<uint8_t> SubjectPublicKeyInfo::encode() const {
        return this->to_asn1().encode();
    }

    // Example: SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234, e: 1234}}
    std::ostream& operator<<(std::ostream& os, const SubjectPublicKeyInfo& SPKI){
        os << "SubjectPublicKeyInfo = { "
            << SPKI._algorithm
            << " "
            << SPKI._subject_public_key
            << "} ";
        return os;
    }

    // Example: PKCS::AttributeTypeAndValue ATAV2{"2.5.4.6", "PL"};
    AttributeTypeAndValue::AttributeTypeAndValue(std::string type, std::string value) {
        // if we have to construct the class using the OID and value
        // if we don't give it explicit ASN1_tag it will check the in attributeStringTypeMap map which ASN1_tag should be used for this type
        // if OID is not found, it will assume UTF8_STRING
        // it also calls validate_string_type to check if it doesn't contain any illegal chars
        // I think this code fragment appears some time later but I haven't made an inline for it yet
        try {
            _value_type = attributeStringTypeMap.at(type);
        } catch (const std::out_of_range& e) { 
            _value_type = UTF8_STRING;
        }

        if(CBZ::Utils::validate_string_type(value, _value_type) == false){
            throw std::runtime_error("AttributeTypeAndValue(string, string): attempt to create object with value that contains illegal characters");
        }
        _type = std::move(type);
        _value = std::move(value);
    }

    // Example: PKCS::AttributeTypeAndValue ATAV3{"2.5.4.6", "PL", PRINTABLE_STRING};
    // Here ASN1_tag is defined explicitly so we need check if it's a string type and then if it doesn't contain illega chars
    AttributeTypeAndValue::AttributeTypeAndValue(std::string type, std::string value, ASN1Tag value_type) {
        if(value_type != UTF8_STRING && 
            value_type != IA5_STRING && 
            value_type != PRINTABLE_STRING){
            throw std::runtime_error("AttributeTypeAndValue(string, string, ASN1_tag): values different than strings that are currently not handled");
        }

        if(CBZ::Utils::validate_string_type(_value,_value_type) == false){
            throw std::runtime_error("AttributeTypeAndValue(string, string, ASN1_tag): attempt to create object with value that contains illegal characters");
        }
        _value_type = value_type;
        _type = std::move(type);
        _value = std::move(value);
    }

    ASN1Object AttributeTypeAndValue::to_asn1() const {
        return ASN1Sequence({
            ASN1ObjectIdentifier(_type),
            ASN1String(_value_type, _value)
        });
    }

    std::vector<uint8_t> AttributeTypeAndValue::encode() const {
        return this->to_asn1().encode();
    }

    // I decided not to include value_type in the output as I think it would add unnecessary clutter
    std::ostream& operator<<(
        std::ostream& os,
        const PKCS::AttributeTypeAndValue& atav
    ) {
        os << "AttributeTypeAndValue = {type: " 
            << atav._type 
            << ", value: " 
            << atav._value 
            << "} ";
        return os;
    }

    ASN1Object RelativeDistinguishedName::to_asn1() const {
        std::vector<ASN1Object> components;
        components.reserve(_atavs.size());

        for (auto& atav : _atavs)
            components.push_back(atav.to_asn1());
        
        return ASN1Set(std::move(components));
    }

    std::vector<uint8_t> RelativeDistinguishedName::encode() const {
        return this->to_asn1().encode();
    }

    // Example: RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST}, AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }
    std::ostream& operator<<(std::ostream& os, const RelativeDistinguishedName& rdn) {
        os << "RelativeDistinguishedName = { ";

        const auto& attrs = rdn._atavs;
        // adding each AttributeTypeAndValue to the stream
        for (size_t i = 0; i < attrs.size(); ++i) {
            os << attrs[i];
            // first method of getting rid of trailing comma
            if (i + 1 < attrs.size()) os << ", ";
        }

        os << " }";
        return os;
    }


    RDNSequence::RDNSequence(
        std::vector<std::pair<std::string, std::string>> list
    ) {
        for(auto& [OID, val] : list){
            _rdn_sequence.emplace_back(std::move(OID), std::move(val));
        }
    }

    ASN1Object RDNSequence::to_asn1() const {
        std::vector<ASN1Object> components;

        for (auto& rdn : _rdn_sequence)
            components.push_back(rdn.to_asn1());

        return ASN1Sequence(std::move(components));
    }

    std::vector<uint8_t> RDNSequence::encode() const {
        return this->to_asn1().encode();
    }

    // Example: RDNSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 1.1.1.1, value: TEST} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.2.2.2, value: TSET} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 3.3.3.3, value: SETT}, AttributeTypeAndValue = {type: 4.4.4.4, value: TTES} } ]
    std::ostream& operator<<(std::ostream& os, const RDNSequence& rdn_sequence) {
        os << "RDNSequence = [ ";

        const auto& rdns = rdn_sequence._rdn_sequence;
        // adding each RDN to the stream
        for (size_t i = 0; i < rdns.size(); ++i) {
            os << rdns[i];
            // trailing comma
            if (i + 1 < rdns.size()) os << ", ";
        }

        os << " ] ";
        return os;
    }


    CertificationRequestInfo::CertificationRequestInfo(
        std::vector<std::pair<std::string, std::string>> subject_name,
        CSRSupportedAlgorithms::algorithm_t algorithm,
        mpz_class n,
        mpz_class e,
        std::vector<std::pair<std::string, std::string>> attributes
    ) 
    : _subject_name(std::move(subject_name)),
    _subject_pkinfo(algorithm, std::move(n), std::move(e))
    {
        for(auto& [OID, val] : attributes){
            _attributes.emplace_back(std::move(OID), std::move(val));
        }
    }

    // CertificationRequestInfo::CertificationRequestInfo(
    //     std::vector<std::pair<std::string, std::string>> subject_name,
    //     std::string algorithm,
    //     mpz_class n,
    //     mpz_class e,
    //     std::vector<std::pair<std::string, std::string>> attributes
    // )
    // : _subject_name(std::move(subject_name)),
    // _subject_pkinfo(std::move(algorithm), std::move(n), std::move(e))
    // {
    //     for(auto& [OID, val] : attributes){
    //         _attributes.emplace_back(std::move(OID), std::move(val));
    //     }
    // }

    ASN1Object CertificationRequestInfo::to_asn1() const {
        std::vector<ASN1Object> components = {
            ASN1Integer(_version),
            _subject_name.to_asn1(),
            _subject_pkinfo.to_asn1()
        };

        std::vector<ASN1Object> attrs;
        for (const Attribute& attr : _attributes)
            attrs.push_back(attr.to_asn1());
        
        components.push_back(ASN1Object(CONSTRUCTED_TYPE, std::move(attrs)));

        return ASN1Sequence({
            std::move(components)
        });
    }

    std::vector<uint8_t> CertificationRequestInfo::encode() const {
        return this->to_asn1().encode();
    }

    std::ostream& operator<<(std::ostream& os, const CertificationRequestInfo& cri){
        os  << "CertificationRequest = {"
            << "Version = "<< cri._version << ", "
            << "subjectName = " << cri._subject_name << ", "
            << "subjectPKInfo = " << cri._subject_pkinfo << ", "
            << "attributes = [";

        // comma trailing prevention
        bool first = true;

        // print every attribute
        for(const auto& attr : cri._attributes){
            if(!first) { os << ", "; }
            first = false;
            os << attr;
        }

        os << "] } ";
        return os;
    }

    ASN1Object CertificationRequest::to_asn1() const {
        return ASN1Sequence({
            _certification_request_info.to_asn1(),
            _signature_algorithm.to_asn1(),
            ASN1BitString(_signature)
        });
    }

    std::vector<uint8_t> CertificationRequest::encode() const {
        return this->to_asn1().encode();

    }

    // generate signature for CSR
    std::vector<uint8_t> CertificationRequest::sign(const RSAPrivateKey& private_key){
        try {
            _signature = Signature::RSASSA_PKCS1_V1_5_SIGN(
                private_key,
                _certification_request_info.encode()
            );
            return _signature;
        } catch (std::runtime_error const& e) {
            CBZ::Utils::print_nested(e);
            exit(1);
        }
    }

    // Example:
    // CertificationRequestInfo = {Version = 0, subjectName = RDNSequence = [ RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.6, value: PL} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.8, value: Lesser Poland} }, RelativeDistinguishedName = { AttributeTypeAndValue = {type: 2.5.4.10, value: AGH} } ], subjectPKInfo = SubjectPublicKeyInfo = { AlgorithmIdentifier = {algorithm: 1.2.840.113549.1.1.1, parameters: 0x05 0x00} RSAPublicKey: = {n: 1234567890, e: 987654321}}, attributes = [Attribute = { Type: 1.2.840.113549.1.1.1, values = [ (tag: 12 "example.com") ] }] }
    std::ostream& operator<<(std::ostream& os, CertificationRequest& cr){
        os  << "CertificationRequestInfo = { " 
            << cr._certification_request_info << ", "
            << cr._signature_algorithm << ", "
            << "Signature: "
            
        // print signature's bytes
            << std::hex << std::setfill('0');
        for(uint8_t byte : cr._signature)
            os << std::setw(2) << static_cast<int>(byte);

        os << std::dec << " } ";
        return os;
    }

    namespace CSRSupportedAlgorithms {

        const std::unordered_map<uint32_t, std::string> algorithmMap = {
            {rsaEncryption,             "1.2.840.113549.1.1.1"  },
            {sha256WithRSAEncryption,   "1.2.840.113549.1.1.11" },
            {sha256,                    "2.16.840.1.101.3.4.2.1"},
        };
    }

    namespace PrivateKeySupportedAlgorithms {

        using namespace PrivateKeyAlgorithms;
        using namespace EncryptionAlgorithms;
        using namespace KDFs;
        using namespace HMACFunctions;
        using namespace EncryptionSchemes;

        const OID RSAEncryption::oid = "1.2.840.113549.1.1.1";
        const OID PBES2::oid = "1.2.840.113549.1.5.13";
        const OID PBKDF2::oid = "1.2.840.113549.1.5.12";
        const OID HMACWithSHA256::oid = "1.2.840.113549.2.9";
        const OID AES::AES_128_CBC::oid = "2.16.840.1.101.3.4.1.2";
        const OID AES::AES_256_CBC::oid = "2.16.840.1.101.3.4.1.42";

        const std::unordered_map<OID, PrivateKeyAlgorithmsEnum> PrivateKeyAlgorithms::privateKeyAlgorithmsMap = {
            { RSAEncryption::oid, PrivateKeyAlgorithmsEnum::rsaEncryption }
        };
        const std::unordered_map<OID, EncryptionAlgorithmsEnum> EncryptionAlgorithms::encryptionAlgorithmsMap = {
            { PBES2::oid, EncryptionAlgorithmsEnum::pbes2 }
        };
        const std::unordered_map<OID, KDFsEnum> KDFs::kdfsMap = {
            { PBKDF2::oid, KDFsEnum::pbkdf2 }
        };
        const std::unordered_map<OID, HMACFunctionsEnum> HMACFunctions::hmacFunctionsMap = {
            { HMACWithSHA256::oid, HMACFunctionsEnum::hmacWithSHA256 }
        };
        const std::unordered_map<OID, EncryptionSchemesEnum> EncryptionSchemes::encryptionSchemesMap = {
            { AES::AES_128_CBC::oid, EncryptionSchemesEnum::aes_128_CBC },
            { AES::AES_256_CBC::oid, EncryptionSchemesEnum::aes_256_CBC }
        };

        int RSAEncryption::validate_parameters(
            const ASN1Object& parameters_object
        ) {
            if (parameters_object.tag() != ASN1Tag::NULL_TYPE)
                return ERR_SEMANTIC_CHECK_FAILED;

            return ERR_OK;
        }

        int PBES2::extract_parameters(
            const ASN1Object& parameters_object,
            struct Parameters* out_ptr
        ) {
            using namespace PrivateKeySupportedAlgorithms;

            if (parameters_object.tag() != ASN1Tag::SEQUENCE)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            auto kdf = parameters_object.children()[0];
            auto enc = parameters_object.children()[1];
            
            struct AlgorithmIdentifier kdf_ai;
            struct AlgorithmIdentifier enc_ai;

            if (int result = KDFs::extract_algorithm(kdf, &kdf_ai); result != ERR_OK)
                return result;

            if (int result = EncryptionSchemes::extract_algorithm(enc, &enc_ai); result != ERR_OK)
                return result;

            if (out_ptr) {
                *out_ptr = Parameters{
                    kdf_ai,
                    enc_ai
                };
            }

            return ERR_OK;
        }

        int PBES2::decrypt_data(
            struct Parameters* params,
            std::shared_ptr<std::string const> passphrase,
            std::span<uint8_t const> in,
            std::vector<uint8_t>& out
        ) {
            using namespace PrivateKeySupportedAlgorithms;

            size_t key_length;
            std::vector<uint8_t> ok;

            switch (params->enc.algorithm) {
                case EncryptionSchemes::aes_128_CBC:
                    key_length = 16;
                    break;
                case EncryptionSchemes::aes_256_CBC:
                    key_length = 32;
                    break;
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }

            switch (params->kdf.algorithm) {
                case KDFs::pbkdf2: {
                    int result = PBKDF2::derive_key(
                        std::static_pointer_cast<PBKDF2::Parameters>(params->kdf.params).get(),
                        passphrase,
                        key_length,
                        ok
                    );
                    if (result != ERR_OK)
                        return result;
                    if (ok.size() != key_length)
                        throw std::runtime_error("[PBKDF2::derive_key] Declared key length was ignored");
                    break;
                }
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }

            switch (params->enc.algorithm) {
                case EncryptionSchemes::aes_128_CBC: {
                    EncryptionSchemes::AES::Parameters* es_params =
                        std::static_pointer_cast
                        <EncryptionSchemes::AES::Parameters>
                        (params->enc.params).get();
                    CBZ::AES::AES_128_CBC::decrypt(
                        in,
                        ok.data(),
                        es_params->iv,
                        out
                    );
                    return ERR_OK;
                }
                case EncryptionSchemes::aes_256_CBC: {
                    EncryptionSchemes::AES::Parameters* es_params =
                        std::static_pointer_cast
                        <EncryptionSchemes::AES::Parameters>
                        (params->enc.params).get();
                    CBZ::AES::AES_256_CBC::decrypt(
                        in,
                        ok.data(),
                        es_params->iv,
                        out
                    );
                    return ERR_OK;
                }
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }
        }

        int PBKDF2::extract_parameters(
            const ASN1Object& parameters_object,
            struct Parameters* out_ptr
        ) {
            if (parameters_object.tag() != ASN1Tag::SEQUENCE)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object.children().size() < 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            uint32_t iteration_count = 0;
            uint32_t key_length = 0;
            AlgorithmIdentifier prf = {
                HMACFunctions::hmacWithSHA1,
                std::shared_ptr<void>(nullptr)
            };

            const ASN1Object& salt = parameters_object.children()[0];
            if (salt.tag() != ASN1Tag::OCTET_STRING)
                return ERR_SEMANTIC_CHECK_FAILED;

            mpz_class _iteration_count_mpz = static_cast<const ASN1Integer&>(parameters_object.children()[1]).value();
            if (_iteration_count_mpz > 0xFFFFFFFF) // This should never happen, but just in case
                return ERR_FEATURE_UNSUPPORTED;
            
            iteration_count = static_cast<uint32_t>(_iteration_count_mpz.get_ui());
            
            // Small bitmap to help with further field extraction
            // 1st LSB stands for the keyLength, while 2nd LSB stands for the prf
            uint8_t _bm = 0; 

            for (size_t i = 2; i < parameters_object.children().size(); i++) {
                auto next_field = parameters_object.children()[i];
                switch (next_field.tag()) {
                    case ASN1Tag::INTEGER: {
                        // Optional keyLength
                        if (_bm  & 0x01 || _bm  & 0x02)
                            // We either see the INTEGER for the second time, or already parsed the prf
                            // Either way, abort
                            return ERR_SEMANTIC_CHECK_FAILED;

                        mpz_class _key_length = static_cast<const ASN1Integer&>(parameters_object.children()[2]).value();
                        if (_key_length > 0xFFFFFFFF) // This also should never happen, but again, just in case
                            return ERR_FEATURE_UNSUPPORTED;
                        
                        key_length = _key_length.get_ui();
                        _bm |= 0x01;
                        break;
                    }
                    case ASN1Tag::SEQUENCE: {
                        // prf
                        if (_bm  & 0x02)
                            // We've already been there; abort
                            return ERR_SEMANTIC_CHECK_FAILED;

                        // Try to extract the algorithm
                        AlgorithmIdentifier _prf;
                        if (int result = PrivateKeySupportedAlgorithms::extract_algorithm(next_field, &_prf); result != 0)
                            return result;

                        prf = _prf;
                        _bm |= 0x02;
                        break;
                    }
                    default:
                        return ERR_SEMANTIC_CHECK_FAILED;
                }
            }
            
            // Finish up; copy data if needed and return
            if (out_ptr) {
               * out_ptr = PBKDF2::Parameters{
                    std::make_shared<std::vector<uint8_t>>(salt.value()),
                    iteration_count,
                    key_length,
                    prf
                };
            }

            return ERR_OK;
        }

        int PBKDF2::derive_key(
            struct Parameters* params,
            std::shared_ptr<std::string const> passphrase,
            size_t key_length,
            std::vector<uint8_t>& out_key
        ) {
            switch (params->prf.algorithm) {
                case HMACFunctions::hmacWithSHA1: {
                    out_key.resize(key_length);
                    CBZ::KDF::PBKDF2<HMAC<SHA::SHA1>>::derive_key(
                        std::span{reinterpret_cast<uint8_t const*>(passphrase->data()), passphrase->size()},
                        std::span{*params->salt},
                        params->iterationCount,
                        key_length,
                        out_key.data()
                    );
                    return ERR_OK;
                }
                case HMACFunctions::hmacWithSHA256: {
                    out_key.resize(key_length);
                    CBZ::KDF::PBKDF2<HMAC<SHA::SHA256>>::derive_key(
                        std::span{reinterpret_cast<uint8_t const*>(passphrase->data()), passphrase->size()},
                        std::span{*params->salt},
                        params->iterationCount,
                        key_length,
                        out_key.data()
                    );
                    return ERR_OK;
                }
                default:
                    return ERR_ALGORITHM_UNSUPPORTED;
            }
        }

        int HMACFunctions::_generic_validate_parameters(
            const ASN1Object& parameters_object
        ) {
            if (parameters_object.tag() != ASN1Tag::NULL_TYPE)
                return ERR_SEMANTIC_CHECK_FAILED;

            return ERR_OK;
        }

        int EncryptionSchemes::AES::extract_parameters(
            const ASN1Object& parameters_object,
            struct Parameters* out_ptr
        ) {
            constexpr const size_t IV_SIZE = 16;

            if (parameters_object.tag() != ASN1Tag::OCTET_STRING)
                return ERR_SEMANTIC_CHECK_FAILED;
            if (parameters_object.value().size() != IV_SIZE)
                return ERR_SEMANTIC_CHECK_FAILED;
            
            if (out_ptr != nullptr) {
                std::memcpy(
                    out_ptr->iv,
                    parameters_object.value().data(),
                    IV_SIZE
                );
            } 
            return ERR_OK;
        }

        int PrivateKeyAlgorithms::extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr,
            const std::string& oid
        ) {
            if (algorithm.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value() : oid;
            auto parameters = algorithm.children()[1];

            // PrivateKeyAlgorithms
            if (
                auto search = PrivateKeySupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.find(algorithm_oid);
                search != PrivateKeySupportedAlgorithms::PrivateKeyAlgorithms::privateKeyAlgorithmsMap.end()
            ) {
                using namespace PrivateKeySupportedAlgorithms::PrivateKeyAlgorithms;
                switch (search->second) {
                    case rsaEncryption: {
                        if (int result = RSAEncryption::validate_parameters(parameters); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                rsaEncryption,
                                std::shared_ptr<void>(nullptr)
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::PrivateKeyAlgorithms::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int EncryptionAlgorithms::extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr,
            const std::string& oid
        ) {
            if (algorithm.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value() : oid;
            auto parameters = algorithm.children()[1];

            // EncryptionAlgorithms
            if (
                auto search = PrivateKeySupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.find(algorithm_oid);
                search != PrivateKeySupportedAlgorithms::EncryptionAlgorithms::encryptionAlgorithmsMap.end()
            ) {
                using namespace PrivateKeySupportedAlgorithms::EncryptionAlgorithms;
                switch (search->second) {
                    case pbes2: {
                        auto pbes2_parameters = out_ptr ? 
                            std::make_shared<PBES2::Parameters>() : std::shared_ptr<PBES2::Parameters>(nullptr);
                        if (int result = PBES2::extract_parameters(parameters, pbes2_parameters.get()); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                pbes2,
                                pbes2_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::EncryptionAlgorithms::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int KDFs::extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr,
            const std::string& oid
        ) {
            if (algorithm.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value() : oid;
            auto parameters = algorithm.children()[1];

            // KDFs
            if (
                auto search = PrivateKeySupportedAlgorithms::KDFs::kdfsMap.find(algorithm_oid);
                search != PrivateKeySupportedAlgorithms::KDFs::kdfsMap.end()
            ) {
                using namespace PrivateKeySupportedAlgorithms::KDFs;
                switch (search->second) {
                    case pbkdf2: {
                        auto pbkdf2_parameters = out_ptr ?
                            std::make_shared<PBKDF2::Parameters>() : std::shared_ptr<PBKDF2::Parameters>(nullptr);
                        if (int result = PBKDF2::extract_parameters(parameters, pbkdf2_parameters.get()); result != ERR_OK)
                            return result;
                        
                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                pbkdf2,
                                pbkdf2_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::KDFs::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int HMACFunctions::extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr,
            const std::string& oid
        ) {
            if (algorithm.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value() : oid;
            auto parameters = algorithm.children()[1];

            // HMACFunctions
            if (
                auto search = PrivateKeySupportedAlgorithms::HMACFunctions::hmacFunctionsMap.find(algorithm_oid);
                search != PrivateKeySupportedAlgorithms::HMACFunctions::hmacFunctionsMap.end()
            ) {
                using namespace PrivateKeySupportedAlgorithms::HMACFunctions;
                switch (search->second) {
                    case hmacWithSHA1:
                    case hmacWithSHA256: {
                        if (int result = _generic_validate_parameters(parameters); result != ERR_OK)
                            return result;

                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                search->second,
                                std::shared_ptr<void>(nullptr)
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::HMACFunctions::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }

        int EncryptionSchemes::extract_algorithm(
            const ASN1Object& algorithm,
            struct AlgorithmIdentifier* out_ptr,
            const std::string& oid
        ) {
            if (algorithm.children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;

            const std::string algorithm_oid = (oid.empty()) ? 
                static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value() : oid;
            auto parameters = algorithm.children()[1];

            // EncryptionSchemes
            if (
                auto search = PrivateKeySupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.find(algorithm_oid);
                search != PrivateKeySupportedAlgorithms::EncryptionSchemes::encryptionSchemesMap.end()
            ) {
                using namespace PrivateKeySupportedAlgorithms::EncryptionSchemes;
                switch (search->second) {
                    case aes_128_CBC: 
                    case aes_256_CBC: {
                        auto aes_parameters = out_ptr ?
                            std::make_shared<EncryptionSchemes::AES::Parameters>()
                            : std::shared_ptr<EncryptionSchemes::AES::Parameters>(nullptr);
                        if (
                            int result = EncryptionSchemes::AES
                            ::extract_parameters(parameters, aes_parameters.get());
                            result != ERR_OK
                        )
                            return result;
                        
                        if (out_ptr) {
                            *out_ptr = AlgorithmIdentifier{
                                search->second,
                                aes_parameters
                            };
                        }
                        return ERR_OK;
                    }
                    default:
                        throw std::runtime_error("[PKCS::EncryptionSchemes::extract_algorithm] Matched something in the map, but not exactly... call the cops should you see this");
                }
            }

            return ERR_ALGORITHM_UNSUPPORTED;
        }
    }

    namespace Labels {
        const std::string privateKeyHeader = "-----BEGIN PRIVATE KEY-----";
        const std::string privateKeyFooter = "-----END PRIVATE KEY-----";
        const std::string encryptedPrivateKeyHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        const std::string encryptedPrivateKeyFooter = "-----END ENCRYPTED PRIVATE KEY-----";
    }

    int PrivateKeySupportedAlgorithms::extract_algorithm(
        const ASN1Object& algorithm,
        struct AlgorithmIdentifier* out_ptr
    ) {
        if (algorithm.children().size() != 2)
            return ERR_SEMANTIC_CHECK_FAILED;

        auto algorithm_oid = static_cast<const ASN1ObjectIdentifier&>(algorithm.children()[0]).value();
        auto parameters = algorithm.children()[1];

        // Iterate through all supported algorithm categories

        int result;
        result = PrivateKeyAlgorithms::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED) // If algorithm was supported, we could succeed or fail; either way return
            return result;
        
        result = EncryptionAlgorithms::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = KDFs::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = HMACFunctions::extract_algorithm(algorithm ,out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        result = EncryptionSchemes::extract_algorithm(algorithm, out_ptr, algorithm_oid);
        if (result != ERR_ALGORITHM_UNSUPPORTED)
            return result;

        return ERR_ALGORITHM_UNSUPPORTED;
    }
}
