#include "csr.h"
#include "fstream"
#include "utils/base64.h"
#include "utils/labels.h"
#include "utils/utils.hpp"
#include "pkcs/sign.h"

namespace CBZ::PKCS {
using namespace CBZ::ASN1;
using namespace CBZ::Security;


int _CertificationRequest_decode(ASN1Object& root_object, CertificationRequest *out);

// this function is almost identicial to RSAPrivateKey::from_file()
CertificationRequest CertificationRequest::from_file(const std::string& filepath){
    std::ifstream csrfile(filepath);
    std::string line1, line2, csr_asn1_b64 = "";

    std::getline(csrfile, line1);
    if (line1 != Labels::certificateRequestHeader)
        throw SemanticCheckException("[CertificationRequest::from_file] CSR header doesn't match the standard");

    std::getline(csrfile, line1);
    while (std::getline(csrfile, line2)) {
        csr_asn1_b64 += line1;
        line1 = line2;
    }

    if (line1 != PKCS::Labels::certificateRequestFooter)
        throw SemanticCheckException("[CertificationRequest::from_file] CSR footer doesn't match the standard");

    std::vector<uint8_t> csr_asn1 = Base64::decode(csr_asn1_b64);
    ASN1Object asn1_root = ASN1Object::decode(std::move(csr_asn1));

    CertificationRequest CSR;
    int result =_CertificationRequest_decode(asn1_root, &CSR);

    switch (result) {
        case ERR_SEMANTIC_CHECK_FAILED:
            throw SemanticCheckException("[CertificationRequest::from_file] semantic check failed");
        case ERR_FEATURE_UNSUPPORTED:
            throw FeatureUnsupportedException("[CertificationRequest::from_file] feature is unsupported");
        case ERR_ALGORITHM_UNSUPPORTED:
            throw AlgorithmUnsupportedException("[CertificationRequest::from_file] algorithm is unsupported");
        case ERR_SIGNATURE_CHECK_FAILED:
            throw SignatureCheckException("[CertificationRequest::from_file] signature check failed");
        default:
            throw std::runtime_error("[CertificationRequest::from_file] unknown error");
    }
    return CSR;
}


//    SubjectPublicKeyInfo  ::=  SEQUENCE  {
//      algorithm            AlgorithmIdentifier,
//      subjectPublicKey     BIT STRING  }


int _RSAPublicKey_check_and_expand(ASN1::ASN1Object& root_object, uint32_t algorithm){
    ASN1Object& public_key = root_object._children[1];
    switch (algorithm) {
        case CSRSupportedAlgorithms::rsaEncryption: {
        if (public_key.children().size() == 0) {
            // NOTE the offset=1
            // ASN1Parser is really awkward when it comes to handling BIT_STRING
            // it treates the the byte that contains the number of unsued bits as _value
            // it's not _value the same way as _tag and _length isn't
            ASN1Object pk_sequence = ASN1Parser::decode_all(std::move(public_key.value()),1);
            // Must contain 2 integers
                if (pk_sequence.children().size() != 2)
                    return ERR_SEMANTIC_CHECK_FAILED;

                public_key._children.push_back(pk_sequence);
            } else if (public_key.children()[0].children().size() != 2)
                return ERR_SEMANTIC_CHECK_FAILED;
            return ERR_OK;
        }
        default:
            return ERR_ALGORITHM_UNSUPPORTED;
    }
}

int _subjectPKInfo_decode(const ASN1Object& root_object, SubjectPublicKeyInfo *out){
    if (
        root_object.tag() != ASN1Tag::SEQUENCE
        || root_object.children().size() != 2
    )
        return ERR_SEMANTIC_CHECK_FAILED;

    AlgorithmIdentifier alg_id;
    const ASN1Object& algorithm_ASN1 = root_object.children()[0];
    if (
        int result = CSRSupportedAlgorithms::PublicKeyAlgorithms::extract_algorithm(algorithm_ASN1, &alg_id); result != 0
    )
        return result;

    // We have to cast away constness to add children
    // There maybe a better way to achive this but this is explicit enough for me
    // we shouldn't be able to modify the root_object but we have to make this exception becuase of how ASN1 parser is designed
    if( int result = _RSAPublicKey_check_and_expand(const_cast<ASN1Object&>(root_object), alg_id.algorithm); result != 0)
        return result;

    const ASN1Object& public_key = root_object.children()[1];
    mpz_class n = static_cast<const ASN1::ASN1Integer&>(public_key.children()[0].children()[0]).value();
    mpz_class e = static_cast<const ASN1::ASN1Integer&>(public_key.children()[0].children()[1]).value();


    *out = SubjectPublicKeyInfo(std::move(alg_id), std::move(RSAPublicKey( std::move(n), std::move(e) )));
    return ERR_OK;
}
//  CertificationRequestInfo ::= SEQUENCE {
//      version       INTEGER { v1(0) } (v1, ... ),
//      subject       Name,
//      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
//      attributes    [0] Attributes{{ CRIAttributes }}
//  }

int _Subject_name_decode(const ASN1Object& root_object, RDNSequence *out) {
    if (
        root_object.tag() != ASN1Tag::SEQUENCE
    )
        return ERR_SEMANTIC_CHECK_FAILED;

    std::vector<RelativeDistinguishedName> RDNS;
    for (int i = 0; i < root_object.children().size(); i++){
        const ASN1Object& rdns_asn1 = root_object.children()[i];
        if (rdns_asn1.tag() != ASN1Tag::SET)
            return  ERR_SEMANTIC_CHECK_FAILED;
        std::vector<AttributeTypeAndValue> RDN;
        for (int j = 0; j < rdns_asn1.children().size(); j++){
            const ASN1Object& atv_asn1 = rdns_asn1.children()[j];
            if(
                atv_asn1.tag() != ASN1Tag::SEQUENCE ||
                atv_asn1.children().size() != 2
            )
                return ERR_SEMANTIC_CHECK_FAILED;
            std::string oid = static_cast<const ASN1ObjectIdentifier&>(atv_asn1.children()[0]).value();
            // As mentioned in other places it is allowed by the standard to have an
            // AttributeTypeAndValue that doesn't contain a string;
            // But we don't need to prepare for that occassion as we are not even
            // likely to allow user to create such CSR; 
            // It would require us to allow for creation of csr.conf file or similar 
            // that would allow for RDN with OID chosen by the user; 
            // I don't see the point in bothering and handling ALL possible types;
            // It will work without it and common certs issued to the website won't even use it;
            // It is also not very uncommon to do that as this is what Active Directory does:
            // https://www.gradenegger.eu/en/permitted-relative-distinguished-names-rdns-in-certificates/
            // https://learn.microsoft.com/en-us/windows/win32/seccrypto/name-properties
            // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772812(v=ws.10)?redirectedfrom=MSDN
            ASN1::ASN1Tag string_tag = atv_asn1.children()[1].tag();
            if(
                string_tag != UTF8_STRING &&
                string_tag != PRINTABLE_STRING &&
                string_tag != IA5_STRING
            )
                return ERR_FEATURE_UNSUPPORTED;
            std::string value = static_cast<const ASN1String&>(atv_asn1.children()[1]).value();
            RDN.emplace_back(AttributeTypeAndValue(std::move(oid), std::move(value), string_tag));
        }
        RDNS.emplace_back(RelativeDistinguishedName(std::move(RDN)));
    }
    *out = RDNSequence(std::move(RDNS));
    return ERR_OK;
}

int _Attributes_decode(const ASN1Object& root_object, std::vector<Attribute> *out) {
    // Weird constructed type
    if (
        root_object.tag() != ASN1::ASN1Tag::CONSTRUCTED_TYPE
    )
        return ERR_SEMANTIC_CHECK_FAILED;

    for (int i = 0; i < root_object.children().size(); i++){
        const ASN1Object& curr_asn1 = root_object.children()[i];
        if(
            curr_asn1.tag() != ASN1Tag::SEQUENCE ||
            curr_asn1.children().size() != 2
        )
            return ERR_SEMANTIC_CHECK_FAILED;

        std::string oid = static_cast<const ASN1ObjectIdentifier&>(curr_asn1.children()[0]).value();

        const ASN1Object& values_asn1 = curr_asn1.children()[1];
        std::vector<std::pair<std::string, ASN1::ASN1Tag>> set_of_values;
        for(int j = 0; j < values_asn1.children().size(); j++){
            const ASN1Object& value_asn1 = values_asn1.children()[j];
            // as with AttributeTypeAndValue for now we only handle strings
            ASN1Tag string_tag = value_asn1.tag();
            if(
                string_tag != UTF8_STRING &&
                string_tag != PRINTABLE_STRING &&
                string_tag != IA5_STRING
            )
                return ERR_FEATURE_UNSUPPORTED;
            std::string value = static_cast<const ASN1String&>(value_asn1).value();
            set_of_values.emplace_back(std::make_pair(value,string_tag));
        }

        (*out).emplace_back(std::move(oid), std::move(set_of_values));
    }
    return ERR_OK;
}


int _CertificationRequestInfo_decode(const ASN1Object& root_object, CertificationRequestInfo *out){
    if (
        root_object.tag() != ASN1Tag::SEQUENCE
        || root_object.children().size() != 4
    )
        return ERR_SEMANTIC_CHECK_FAILED;

    const ASN1Object& version_ASN1 = root_object.children()[0];
    if (version_ASN1.tag() != ASN1Tag::INTEGER) // 'version' must be of type INTEGER
        return ERR_SEMANTIC_CHECK_FAILED;
    if (int version = static_cast<const ASN1Integer&>(version_ASN1).value().get_ui(); version != 0) // 'version' must be equal to 0
            return ERR_FEATURE_UNSUPPORTED;


    const ASN1Object& Name_ASN1 = root_object.children()[1];
    RDNSequence RDNS;
    if (int result = _Subject_name_decode(Name_ASN1, &RDNS); result != ERR_OK)
        return result;

    const ASN1Object& subjectPKInfo_ASN1 = root_object.children()[2];
    SubjectPublicKeyInfo SPKI;
    if (int result = _subjectPKInfo_decode(subjectPKInfo_ASN1, &SPKI); result != ERR_OK)
        return result;

    const ASN1Object& Attributes_ASN1 = root_object.children()[3];
    std::vector<Attribute> attrs;
    if (int result = _Attributes_decode(Attributes_ASN1, &attrs); result != ERR_OK)
        return result;

    *out = CertificationRequestInfo(std::move(RDNS), std::move(SPKI), std::move(attrs));
    return ERR_OK;
}

//  CertificationRequest ::= SEQUENCE {
//       certificationRequestInfo CertificationRequestInfo,
//       signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
//       signature          BIT STRING
//  }
int _CertificationRequest_decode(ASN1Object& root_object, CertificationRequest *out) {
    // CSR object contains 3 children
    if (
        root_object.tag() != ASN1Tag::SEQUENCE
        || root_object.children().size() != 3
    )
        return ERR_SEMANTIC_CHECK_FAILED;

    const ASN1Object& certificationRequestInfo_ASN1 = root_object.children()[0];
    // Intialize empty CRI object that will be filled by the call to _CertificationRequestInfo_decode
    CertificationRequestInfo CRI;
    if (int result = _CertificationRequestInfo_decode(certificationRequestInfo_ASN1, &CRI); result != ERR_OK)
        return result;


    const ASN1Object& signatureAlgorithm_ASN1 = root_object.children()[1];
    struct AlgorithmIdentifier alg_id;
    if (int result = CSRSupportedAlgorithms::SignatureAlgorithms::extract_algorithm(signatureAlgorithm_ASN1, &alg_id); result != ERR_OK)
        return result;

    *out = CertificationRequest(std::move(CRI), std::move(alg_id));

    std::cout << *out << std::endl;




    // verify signature
    // get public key from certification certification request
    const RSAPublicKey& pub_key = (*out).getPublicKeyReference();

    // get certifcationRequestInfo encoded as DER (that's the part of CSR that is actually signed)
    const std::vector<uint8_t>& mess = (*out).getCertificationRequestInfoReference().encode();

    // get signature
    const ASN1Object& signature_ASN1 = root_object.children()[2];
    if (signature_ASN1.tag() != ASN1Tag::BIT_STRING) // 'signature' is a BITSTRING
        return ERR_SEMANTIC_CHECK_FAILED;
    // Again it's skipping the first byte for BIT_STRING is a bit awkward
    // I could maybe modify RSASSA_PKCS1_V1_5_VERIFY to accept Iterator and it would probably be better
    // But I don't what to change that part for now
    std::vector<uint8_t>& s_ref = const_cast<std::vector<uint8_t>&>(signature_ASN1.value());
    std::vector<uint8_t> signature(s_ref.begin() + 1, s_ref.end());
    // verify signature
    if(!Signature::RSASSA_PKCS1_V1_5_VERIFY(pub_key, mess, signature))
        return ERR_SIGNATURE_CHECK_FAILED;

    return ERR_OK;
}

}
