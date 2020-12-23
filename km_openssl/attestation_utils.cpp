/*
**
** Copyright 2017, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <keymaster/km_openssl/attestation_utils.h>
#include <keymaster/km_openssl/certificate_utils.h>

#include <hardware/keymaster_defs.h>

#include <keymaster/attestation_record.h>
#include <keymaster/authorization_set.h>
#include <keymaster/km_openssl/asymmetric_key.h>
#include <keymaster/km_openssl/openssl_err.h>
#include <keymaster/km_openssl/openssl_utils.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

namespace keymaster {

namespace {

constexpr int kDefaultAttestationSerial = 1;
constexpr const char kDefaultSubject[] = "Android Keystore Key";

CertificateChain makeCertChain(X509* certificate, CertificateChain chain,
                               keymaster_error_t* error) {
    int len = i2d_X509(certificate, nullptr /* ppout */);
    if (len < 0) {
        *error = TranslateLastOpenSslError();
        return {};
    }

    uint8_t* cert_data = new (std::nothrow) uint8_t[len];
    if (!cert_data) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return {};
    }

    uint8_t* p = cert_data;
    i2d_X509(certificate, &p);

    if (!chain.push_front({cert_data, static_cast<size_t>(len)})) {
        *error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
        return {};
    }
    return chain;
}

keymaster_error_t build_attestation_extension(const AuthorizationSet& attest_params,
                                              const AuthorizationSet& tee_enforced,
                                              const AuthorizationSet& sw_enforced,
                                              const AttestationRecordContext& context,
                                              X509_EXTENSION_Ptr* extension) {
    ASN1_OBJECT_Ptr oid(
        OBJ_txt2obj(kAsn1TokenOid, 1 /* accept numerical dotted string form only */));
    if (!oid.get()) return TranslateLastOpenSslError();

    UniquePtr<uint8_t[]> attest_bytes;
    size_t attest_bytes_len;
    keymaster_error_t error = build_attestation_record(attest_params, sw_enforced, tee_enforced,
                                                       context, &attest_bytes, &attest_bytes_len);
    if (error != KM_ERROR_OK) return error;

    ASN1_OCTET_STRING_Ptr attest_str(ASN1_OCTET_STRING_new());
    if (!attest_str.get() ||
        !ASN1_OCTET_STRING_set(attest_str.get(), attest_bytes.get(), attest_bytes_len)) {
        return TranslateLastOpenSslError();
    }

    extension->reset(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0 /* not critical */, attest_str.get()));
    if (!extension->get()) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

keymaster_error_t build_eat_extension(const AuthorizationSet& attest_params,
                                      const AuthorizationSet& tee_enforced,
                                      const AuthorizationSet& sw_enforced,
                                      const AttestationRecordContext& context,
                                      X509_EXTENSION_Ptr* extension) {
    ASN1_OBJECT_Ptr oid(
        OBJ_txt2obj(kEatTokenOid, 1 /* accept numerical dotted string form only */));
    if (!oid.get()) {
        return TranslateLastOpenSslError();
    }

    std::vector<uint8_t> eat_bytes;
    keymaster_error_t error =
        build_eat_record(attest_params, sw_enforced, tee_enforced, context, &eat_bytes);
    if (error != KM_ERROR_OK) return error;

    ASN1_OCTET_STRING_Ptr eat_str(ASN1_OCTET_STRING_new());
    if (!eat_str.get() ||
        !ASN1_OCTET_STRING_set(eat_str.get(), eat_bytes.data(), eat_bytes.size())) {
        return TranslateLastOpenSslError();
    }

    extension->reset(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0 /* not critical */, eat_str.get()));
    if (!extension->get()) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

keymaster_error_t add_attestation_extension(const AuthorizationSet& attest_params,
                                            const AuthorizationSet& tee_enforced,
                                            const AuthorizationSet& sw_enforced,
                                            const AttestationRecordContext& context,
                                            X509* certificate) {
    X509_EXTENSION_Ptr attest_extension;
    if (context.GetKmVersion() < KmVersion::KEYMINT_1) {
        if (auto error = build_attestation_extension(attest_params, tee_enforced, sw_enforced,
                                                     context, &attest_extension)) {
            return error;
        }
    } else {
        if (auto error = build_eat_extension(attest_params, tee_enforced, sw_enforced, context,
                                             &attest_extension)) {
            return error;
        }
    }

    if (!X509_add_ext(certificate, attest_extension.get() /* Don't release; copied */,
                      -1 /* insert at end */)) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

}  // anonymous namespace

keymaster_error_t
make_attestation_cert(const EVP_PKEY* evp_pkey, const uint32_t serial, const X509_NAME* subject,
                      const X509_NAME* issuer, const uint64_t activeDateTimeMilliSeconds,
                      const uint64_t usageExpireDateTimeMilliSeconds, const bool is_signing_key,
                      const bool is_encryption_key, const AuthorizationSet& attest_params,
                      const AuthorizationSet& tee_enforced, const AuthorizationSet& sw_enforced,
                      const AttestationRecordContext& context, X509_Ptr* cert_out) {

    // First make the basic certificate with usage extension.
    X509_Ptr certificate;
    if (auto error = make_cert(evp_pkey, serial, subject, issuer, activeDateTimeMilliSeconds,
                               usageExpireDateTimeMilliSeconds, is_signing_key, is_encryption_key,
                               &certificate)) {
        return error;
    }

    // Add attestation extension.
    if (auto error = add_attestation_extension(attest_params, tee_enforced, sw_enforced, context,
                                               certificate.get())) {
        return error;
    }

    *cert_out = move(certificate);
    return KM_ERROR_OK;
}

// Generate attestation certificate base on the EVP key and other parameters passed in.
CertificateChain generate_attestation_from_EVP(const EVP_PKEY* evp_key,  //
                                               const AuthorizationSet& sw_enforced,
                                               const AuthorizationSet& tee_enforced,
                                               const AuthorizationSet& attest_params,
                                               const AttestationRecordContext& context,
                                               CertificateChain attestation_chain,
                                               const keymaster_key_blob_t& attestation_signing_key,
                                               keymaster_error_t* error) {
    keymaster_error_t err;
    if (!error) error = &err;

    uint32_t serial = kDefaultAttestationSerial;
    attest_params.GetTagValue(TAG_CERTIFICATE_SERIAL, &serial);

    keymaster_blob_t att_subject = {nullptr, 0};
    X509_NAME_Ptr subjectName;

    if (attest_params.GetTagValue(TAG_CERTIFICATE_SUBJECT, &att_subject) &&
        att_subject.data_length > 0) {
        *error = make_name_from_der(att_subject.data, att_subject.data_length, &subjectName);
        if (*error != KM_ERROR_OK) return {};
    } else {
        *error = make_name_from_str(kDefaultSubject, &subjectName);
        if (*error != KM_ERROR_OK) return {};
    }

    const uint8_t* p = attestation_chain.entries[0].data;
    X509_Ptr signing_cert(d2i_X509(nullptr, &p, attestation_chain.entries[0].data_length));
    if (!signing_cert.get()) {
        *error = TranslateLastOpenSslError();
        return {};
    }

    X509_NAME* issuerSubject = X509_get_subject_name(signing_cert.get());
    if (!issuerSubject) {
        *error = KM_ERROR_UNKNOWN_ERROR;
        return {};
    }

    uint64_t activeDateTime = 0;
    attest_params.GetTagValue(TAG_ACTIVE_DATETIME, &activeDateTime);

    uint64_t usageExpireDateTime = UINT64_MAX;
    attest_params.GetTagValue(TAG_USAGE_EXPIRE_DATETIME, &usageExpireDateTime);

    bool is_signing_key = tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_SIGN) ||
                          tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_VERIFY) ||
                          sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_SIGN) ||
                          sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_VERIFY);

    bool is_encryption_key = tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_ENCRYPT) ||
                             tee_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_DECRYPT) ||
                             sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_ENCRYPT) ||
                             sw_enforced.Contains(TAG_PURPOSE, KM_PURPOSE_DECRYPT);

    X509_Ptr certificate;
    *error =
        make_attestation_cert(evp_key, serial, subjectName.get(), issuerSubject, activeDateTime,
                              usageExpireDateTime, is_signing_key, is_encryption_key, attest_params,
                              tee_enforced, sw_enforced, context, &certificate);
    if (*error != KM_ERROR_OK) return {};

    *error = sign_cert(certificate.get(), signing_cert.get(), attestation_signing_key);
    if (*error != KM_ERROR_OK) return {};

    return makeCertChain(certificate.get(), move(attestation_chain), error);
}

// Generate attestation certificate base on the AsymmetricKey key and other parameters
// passed in.  In attest_params, we expect the challenge, active time and expiration
// time, and app id.
//
// The active time and expiration time are expected in milliseconds.
//
// Hardware and software enforced AuthorizationSet are expected to be built into the AsymmetricKey
// input. In hardware enforced AuthorizationSet, we expect hardware related tags such as
// TAG_IDENTITY_CREDENTIAL_KEY.
CertificateChain generate_attestation(const AsymmetricKey& key,
                                      const AuthorizationSet& attest_params,
                                      CertificateChain attestation_chain,
                                      const keymaster_key_blob_t& attestation_signing_key,
                                      const AttestationRecordContext& context,
                                      keymaster_error_t* error) {

    // assume the conversion to EVP key correctly encodes the key type such
    // that EVP_PKEY_type(evp_key->type) returns correctly.
    EVP_PKEY_Ptr pkey(EVP_PKEY_new());
    if (!key.InternalToEvp(pkey.get())) {
        *error = TranslateLastOpenSslError();
        return {};
    }

    return generate_attestation_from_EVP(pkey.get(), key.sw_enforced(), key.hw_enforced(),
                                         attest_params, context, move(attestation_chain),
                                         attestation_signing_key, error);
}

}  // namespace keymaster
