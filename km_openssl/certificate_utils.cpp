/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/km_openssl/certificate_utils.h>
#include <keymaster/km_openssl/openssl_err.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

#include <hardware/keymaster_defs.h>

namespace keymaster {

namespace {

constexpr int kDigitalSignatureKeyUsageBit = 0;
constexpr int kKeyEnciphermentKeyUsageBit = 2;
constexpr int kDataEnciphermentKeyUsageBit = 3;
constexpr int kMaxKeyUsageBit = 8;

template <typename T> T&& min(T&& a, T&& b) {
    return (a < b) ? forward<T>(a) : forward<T>(b);
}

}  // namespace

keymaster_error_t make_common_name(const char name[], X509_NAME_Ptr* name_out) {
    if (name_out == nullptr) return KM_ERROR_UNEXPECTED_NULL_POINTER;
    X509_NAME_Ptr x509_name(X509_NAME_new());
    if (!x509_name.get()) {
        return TranslateLastOpenSslError();
    }
    if (!X509_NAME_add_entry_by_txt(x509_name.get(),  //
                                    "CN",             //
                                    MBSTRING_ASC, reinterpret_cast<const uint8_t*>(&name[0]),
                                    -1,  // len
                                    -1,  // loc
                                    0 /* set */)) {
        return TranslateLastOpenSslError();
    }
    *name_out = move(x509_name);
    return KM_ERROR_OK;
}

keymaster_error_t get_common_name(X509_NAME* name, UniquePtr<const char[]>* name_out) {
    if (name == nullptr || name_out == nullptr) return KM_ERROR_UNEXPECTED_NULL_POINTER;
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, nullptr, 0);
    UniquePtr<char[]> name_ptr(new (std::nothrow) char[len]);
    if (!name_ptr) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    X509_NAME_get_text_by_NID(name, NID_commonName, name_ptr.get(), len);
    *name_out = UniquePtr<const char[]>{name_ptr.release()};
    return KM_ERROR_OK;
}

keymaster_error_t make_key_usage_extension(bool is_signing_key, bool is_encryption_key,
                                           X509_EXTENSION_Ptr* usage_extension_out) {
    if (usage_extension_out == nullptr) return KM_ERROR_UNEXPECTED_NULL_POINTER;

    // Build BIT_STRING with correct contents.
    ASN1_BIT_STRING_Ptr key_usage(ASN1_BIT_STRING_new());
    if (!key_usage) return KM_ERROR_MEMORY_ALLOCATION_FAILED;

    for (size_t i = 0; i <= kMaxKeyUsageBit; ++i) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), i, 0)) {
            return TranslateLastOpenSslError();
        }
    }

    if (is_signing_key) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kDigitalSignatureKeyUsageBit, 1)) {
            return TranslateLastOpenSslError();
        }
    }

    if (is_encryption_key) {
        if (!ASN1_BIT_STRING_set_bit(key_usage.get(), kKeyEnciphermentKeyUsageBit, 1) ||
            !ASN1_BIT_STRING_set_bit(key_usage.get(), kDataEnciphermentKeyUsageBit, 1)) {
            return TranslateLastOpenSslError();
        }
    }

    // Convert to octets
    int len = i2d_ASN1_BIT_STRING(key_usage.get(), nullptr);
    if (len < 0) {
        return TranslateLastOpenSslError();
    }
    UniquePtr<uint8_t[]> asn1_key_usage(new (std::nothrow) uint8_t[len]);
    if (!asn1_key_usage.get()) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    uint8_t* p = asn1_key_usage.get();
    len = i2d_ASN1_BIT_STRING(key_usage.get(), &p);
    if (len < 0) {
        return TranslateLastOpenSslError();
    }

    // Build OCTET_STRING
    ASN1_OCTET_STRING_Ptr key_usage_str(ASN1_OCTET_STRING_new());
    if (!key_usage_str.get() ||
        !ASN1_OCTET_STRING_set(key_usage_str.get(), asn1_key_usage.get(), len)) {
        return TranslateLastOpenSslError();
    }

    X509_EXTENSION_Ptr key_usage_extension(X509_EXTENSION_create_by_NID(nullptr,        //
                                                                        NID_key_usage,  //
                                                                        true /* critical */,
                                                                        key_usage_str.get()));
    if (!key_usage_extension.get()) {
        return TranslateLastOpenSslError();
    }

    *usage_extension_out = move(key_usage_extension);

    return KM_ERROR_OK;
}

// Creates a rump certificate structure with serial, subject and issuer names, as well as
// activation and expiry date.
// Callers should pass an empty X509_Ptr and check the return value for KM_ERROR_OK (0) before
// accessing the result.
keymaster_error_t make_cert_rump(const uint32_t serial, const char subject[], X509_NAME* issuer,
                                 const uint64_t activeDateTimeMilliSeconds,
                                 const uint64_t usageExpireDateTimeMilliSeconds,
                                 X509_Ptr* cert_out) {

    // Sanitize pointer arguments.
    if (cert_out == nullptr || issuer == nullptr) return KM_ERROR_UNEXPECTED_NULL_POINTER;
    if (!subject || strlen(subject) == 0) {
        return KM_ERROR_INVALID_ARGUMENT;
    }

    // Create certificate structure.
    X509_Ptr certificate(X509_new());
    if (!certificate.get()) {
        return TranslateLastOpenSslError();
    }

    // Set the X509 version.
    if (!X509_set_version(certificate.get(), 2 /* version 3, but zero-based */))
        return TranslateLastOpenSslError();

    // Set the certificate serialNumber
    ASN1_INTEGER_Ptr serialNumber(ASN1_INTEGER_new());
    if (!serialNumber.get() || !ASN1_INTEGER_set(serialNumber.get(), serial) ||
        !X509_set_serialNumber(certificate.get(), serialNumber.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // Set Subject Name
    X509_NAME_Ptr subjectName;
    if (auto error = make_common_name(subject, &subjectName)) {
        return error;
    }
    if (!X509_set_subject_name(certificate.get(), subjectName.get() /* Don't release; copied */)) {
        return TranslateLastOpenSslError();
    }

    if (!X509_set_issuer_name(certificate.get(), issuer)) {
        return TranslateLastOpenSslError();
    }

    // Set activation date.
    ASN1_TIME_Ptr notBefore(ASN1_TIME_new());
    if (!notBefore.get() || !ASN1_TIME_set(notBefore.get(), activeDateTimeMilliSeconds / 1000) ||
        !X509_set_notBefore(certificate.get(), notBefore.get() /* Don't release; copied */))
        return TranslateLastOpenSslError();

    // Set expiration date.
    ASN1_TIME_Ptr notAfter(ASN1_TIME_new());
    // TODO(swillden): When trusty can use the C++ standard library change the calculation of
    // notAfterTime to use std::numeric_limits<time_t>::max(), rather than assuming that time_t
    // is 32 bits.
    time_t notAfterTime;
    notAfterTime =
        (time_t)min(static_cast<uint64_t>(UINT32_MAX), usageExpireDateTimeMilliSeconds / 1000);

    if (!notAfter.get() || !ASN1_TIME_set(notAfter.get(), notAfterTime) ||
        !X509_set_notAfter(certificate.get(), notAfter.get() /* Don't release; copied */)) {
        return TranslateLastOpenSslError();
    }

    *cert_out = move(certificate);
    return KM_ERROR_OK;
}

keymaster_error_t make_cert(const EVP_PKEY* evp_pkey, const uint32_t serial, const char subject[],
                            X509_NAME* issuer, const uint64_t activeDateTimeMilliSeconds,
                            const uint64_t usageExpireDateTimeMilliSeconds,
                            const bool is_signing_key, const bool is_encryption_key,
                            X509_Ptr* cert_out) {

    // Make the rump certificate with serial, subject, not before and not after dates.
    X509_Ptr certificate;
    if (auto error = make_cert_rump(serial, subject, issuer, activeDateTimeMilliSeconds,
                                    usageExpireDateTimeMilliSeconds, &certificate)) {
        return error;
    }

    // Set the public key.
    if (!X509_set_pubkey(certificate.get(), (EVP_PKEY*)evp_pkey)) {
        return TranslateLastOpenSslError();
    }

    // Make and add the key usage extension.
    X509_EXTENSION_Ptr key_usage_extension;
    if (auto error =
            make_key_usage_extension(is_signing_key, is_encryption_key, &key_usage_extension)) {
        return error;
    }
    if (!X509_add_ext(certificate.get(), key_usage_extension.get() /* Don't release; copied */,
                      -1 /* insert at end */)) {
        return TranslateLastOpenSslError();
    }

    *cert_out = move(certificate);
    return KM_ERROR_OK;
}

// Takes a certificate a signing certificate and the raw private signing_key. And signs
// the certificate with the latter.
keymaster_error_t sign_cert(X509* certificate, X509* signing_cert,
                            const keymaster_key_blob_t& signing_key) {

    if (certificate == nullptr || signing_cert == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }

    EVP_PKEY* signing_pkey = X509_get_pubkey(signing_cert);
    if (signing_pkey == nullptr) {
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    int evp_key_type = EVP_PKEY_type(signing_pkey->type);

    const uint8_t* key_material = signing_key.key_material;
    EVP_PKEY_Ptr sign_key(
        d2i_PrivateKey(evp_key_type, nullptr, &key_material, signing_key.key_material_size));
    if (!sign_key) {
        return TranslateLastOpenSslError();
    }

    if (!X509_sign(certificate, sign_key.get(), EVP_sha256())) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

}  // namespace keymaster
