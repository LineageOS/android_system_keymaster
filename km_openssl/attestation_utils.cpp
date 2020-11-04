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

#include <keymaster/authorization_set.h>
#include <keymaster/attestation_record.h>
#include <keymaster/km_openssl/asymmetric_key.h>
#include <keymaster/km_openssl/openssl_utils.h>
#include <keymaster/km_openssl/openssl_err.h>

#include <openssl/x509v3.h>
#include <openssl/evp.h>


namespace keymaster {

namespace {

constexpr int kDefaultAttestationSerial = 1;
constexpr const char kDefaultSubject[] = "Android Keystore Key";

struct emptyCert {};

__attribute__((__unused__))
inline keymaster_blob_t certBlobifier(const emptyCert&, bool*){ return {}; }
template <size_t N>
inline keymaster_blob_t certBlobifier(const uint8_t (&cert)[N], bool* fail){
    keymaster_blob_t result = { dup_array(cert), N };
    if (!result.data) {
        *fail = true;
        return {};
    }
    return result;
}
inline keymaster_blob_t certBlobifier(const keymaster_blob_t& blob, bool* fail){
    if (blob.data == nullptr || blob.data_length == 0) return {};
    keymaster_blob_t result = { dup_array(blob.data, blob.data_length), blob.data_length };
    if (!result.data) {
        *fail = true;
        return {};
    }
    return result;
}
inline keymaster_blob_t certBlobifier(keymaster_blob_t&& blob, bool*){
    if (blob.data == nullptr || blob.data_length == 0) return {};
    keymaster_blob_t result = blob;
    blob = {};
    return result;
}
inline keymaster_blob_t certBlobifier(X509* certificate, bool* fail){
    int len = i2d_X509(certificate, nullptr);
    if (len < 0) {
        *fail = true;
        return {};
    }

    uint8_t* data = new(std::nothrow) uint8_t[len];
    if (!data) {
        *fail = true;
        return {};
    }
    uint8_t* p = data;

    i2d_X509(certificate, &p);

    return { data, (size_t)len };
}

inline bool certCopier(keymaster_blob_t** out, const keymaster_cert_chain_t& chain,
                              bool* fail) {
    for (size_t i = 0; i < chain.entry_count; ++i) {
        *(*out)++ = certBlobifier(chain.entries[i], fail);
    }
    return *fail;
}

__attribute__((__unused__))
inline bool certCopier(keymaster_blob_t** out, keymaster_cert_chain_t&& chain, bool* fail) {
    for (size_t i = 0; i < chain.entry_count; ++i) {
        *(*out)++ = certBlobifier(move(chain.entries[i]), fail);
    }
    delete[] chain.entries;
    chain.entries = nullptr;
    chain.entry_count = 0;
    return *fail;
}
template <typename CERT>
inline bool certCopier(keymaster_blob_t** out, CERT&& cert, bool* fail) {
    *(*out)++ = certBlobifier(forward<CERT>(cert), fail);
    return *fail;
}

inline bool certCopyHelper(keymaster_blob_t**, bool* fail) {
    return *fail;
}

template <typename CERT, typename... CERTS>
inline bool certCopyHelper(keymaster_blob_t** out, bool* fail, CERT&& cert, CERTS&&... certs) {
    certCopier(out, forward<CERT>(cert), fail);
    return certCopyHelper(out, fail, forward<CERTS>(certs)...);
}



template <typename T>
inline size_t noOfCert(T &&) { return 1; }
inline size_t noOfCert(const keymaster_cert_chain_t& cert_chain) { return cert_chain.entry_count; }

inline size_t certCount() { return 0; }
template <typename CERT, typename... CERTS>
inline size_t certCount(CERT&& cert, CERTS&&... certs) {
    return noOfCert(forward<CERT>(cert)) + certCount(forward<CERTS>(certs)...);
}

/*
 * makeCertChain creates a new keymaster_cert_chain_t from all the certs that get thrown at it
 * in the given order. A cert may be a X509*, uint8_t[], a keymaster_blob_t, an instance of
 * emptyCert, or another keymater_cert_chain_t in which case the certs of the chain are included
 * in the new chain. emptyCert is a placeholder which results in an empty slot at the given
 * position in the newly created certificate chain. E.g., makeCertChain(emptyCert(), someCertChain)
 * allocates enough slots to accommodate all certificates of someCertChain plus one empty slot and
 * copies in someCertChain starting at index 1 so that the slot with index 0 can be used for a new
 * leaf entry.
 *
 * makeCertChain respects move semantics. E.g., makeCertChain(emptyCert(), std::move(someCertChain))
 * will take possession of secondary resources for the certificate blobs so that someCertChain is
 * empty after the call. Also, because no allocation happens this cannot fail. Note, however, that
 * if another cert is passed to makeCertChain, that needs to be copied and thus requires
 * allocation, and this allocation fails, all resources - allocated or moved - will be reaped.
 */
template <typename... CERTS>
CertChainPtr makeCertChain(CERTS&&... certs) {
    CertChainPtr result(new (std::nothrow) keymaster_cert_chain_t);
    if (!result.get()) return {};
    result->entries = new (std::nothrow) keymaster_blob_t[certCount(forward<CERTS>(certs)...)];
    if (!result->entries) return {};
    result->entry_count = certCount(forward<CERTS>(certs)...);
    bool allocation_failed = false;
    keymaster_blob_t* entries = result->entries;
    certCopyHelper(&entries, &allocation_failed, forward<CERTS>(certs)...);
    if (allocation_failed) return {};
    return result;
}

keymaster_error_t build_attestation_extension(const AuthorizationSet& attest_params,
                                              const AuthorizationSet& tee_enforced,
                                              const AuthorizationSet& sw_enforced,
                                              const uint keymaster_version,
                                              const AttestationRecordContext& context,
                                              X509_EXTENSION_Ptr* extension) {
    ASN1_OBJECT_Ptr oid(
        OBJ_txt2obj(kAttestionRecordOid, 1 /* accept numerical dotted string form only */));
    if (!oid.get())
        return TranslateLastOpenSslError();

    UniquePtr<uint8_t[]> attest_bytes;
    size_t attest_bytes_len;
    keymaster_error_t error =
        build_attestation_record(attest_params, sw_enforced, tee_enforced, context,
                                 keymaster_version, &attest_bytes, &attest_bytes_len);
    if (error != KM_ERROR_OK)
        return error;

    ASN1_OCTET_STRING_Ptr attest_str(ASN1_OCTET_STRING_new());
    if (!attest_str.get() ||
        !ASN1_OCTET_STRING_set(attest_str.get(), attest_bytes.get(), attest_bytes_len))
        return TranslateLastOpenSslError();

    extension->reset(
        X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 0 /* not critical */, attest_str.get()));
    if (!extension->get())
        return TranslateLastOpenSslError();

    return KM_ERROR_OK;
}

keymaster_error_t add_attestation_extension(const AuthorizationSet& attest_params,
                                            const AuthorizationSet& tee_enforced,
                                            const AuthorizationSet& sw_enforced,
                                            const AttestationRecordContext& context,
                                            const uint keymaster_version, X509* certificate) {
    X509_EXTENSION_Ptr attest_extension;
    if (auto error = build_attestation_extension(attest_params, tee_enforced, sw_enforced,
                                                 keymaster_version, context, &attest_extension)) {
        return error;
    }

    if (!X509_add_ext(certificate, attest_extension.get() /* Don't release; copied */,
                      -1 /* insert at end */)) {
        return TranslateLastOpenSslError();
    }

    return KM_ERROR_OK;
}

}  // anonymous namespace

keymaster_error_t make_attestation_cert(
    const EVP_PKEY* evp_pkey, const uint32_t serial, const char subject[], X509_NAME* issuer,
    const uint64_t activeDateTimeMilliSeconds, const uint64_t usageExpireDateTimeMilliSeconds,
    const bool is_signing_key, const bool is_encryption_key, const AuthorizationSet& attest_params,
    const AuthorizationSet& tee_enforced, const AuthorizationSet& sw_enforced,
    const AttestationRecordContext& context, const uint keymaster_version, X509_Ptr* cert_out) {

    // First make the basic certificate with usage extension.
    X509_Ptr certificate;
    if (auto error = make_cert(evp_pkey, serial, subject, issuer, activeDateTimeMilliSeconds,
                               usageExpireDateTimeMilliSeconds, is_signing_key, is_encryption_key,
                               &certificate)) {
        return error;
    }

    // Add attestation extension.
    if (auto error = add_attestation_extension(attest_params, tee_enforced, sw_enforced, context,
                                               keymaster_version, certificate.get())) {
        return error;
    }

    *cert_out = move(certificate);
    return KM_ERROR_OK;
}

// Generate attestation certificate base on the EVP key and other parameters
// passed in.  Note that due to sub sub sub function call setup, there are 3 AuthorizationSet
// passed in, hardware, software, and attest_params.  In attest_params, we expects the
// challenge, active time and expiration time, and app id.  In hw_enforced, we expects
// hardware related tags such as TAG_IDENTITY_CREDENTIAL_KEY.
//
// The active time and expiration time are expected in milliseconds.
keymaster_error_t generate_attestation_from_EVP(
    const EVP_PKEY* evp_key,                  // input
    const AuthorizationSet& sw_enforced,      // input
    const AuthorizationSet& tee_enforced,     // input
    const AuthorizationSet& attest_params,    // input. Sub function require app id to be set here.
    const AttestationRecordContext& context,  // input
    const uint keymaster_version,             // input
    const keymaster_cert_chain_t& attestation_chain,      // input
    const keymaster_key_blob_t& attestation_signing_key,  // input
    CertChainPtr* cert_chain_out) {                       // Output.

    uint32_t serial = kDefaultAttestationSerial;

    // The default subject is CN=fake
    const char* subject = kDefaultSubject;

    const uint8_t* p = attestation_chain.entries[0].data;
    X509_Ptr signing_cert(d2i_X509(nullptr, &p, attestation_chain.entries[0].data_length));
    if (!signing_cert.get()) {
        return TranslateLastOpenSslError();
    }

    X509_NAME* issuerSubject = X509_get_subject_name(signing_cert.get());
    if (!issuerSubject) {
        return KM_ERROR_UNKNOWN_ERROR;
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
    if (auto error = make_attestation_cert(evp_key, serial, subject, issuerSubject, activeDateTime,
                                           usageExpireDateTime, is_signing_key, is_encryption_key,
                                           attest_params, tee_enforced, sw_enforced, context,
                                           keymaster_version, &certificate)) {
        return error;
    }

    if (auto error = sign_cert(certificate.get(), signing_cert.get(), attestation_signing_key)) {
        return error;
    }

    *cert_chain_out = makeCertChain(certificate.get(), attestation_chain);
    if (!*cert_chain_out) {
        return KM_ERROR_MEMORY_ALLOCATION_FAILED;
    }
    return KM_ERROR_OK;
}

// Generate attestation certificate base on the AsymmetricKey key and other parameters
// passed in.  In attest_params, we expects the challenge, active time and expiration
// time, and app id.
//
// The active time and expiration time are expected in milliseconds.
//
// Hardware and software enforced AuthorizationSet are expected to be built into the AsymmetricKey
// input. In hardware enforced AuthorizationSet, we expects hardware related tags such as
// TAG_IDENTITY_CREDENTIAL_KEY.
keymaster_error_t generate_attestation(const AsymmetricKey& key,
                                       const AuthorizationSet& attest_params,
                                       const keymaster_cert_chain_t& attestation_chain,
                                       const keymaster_key_blob_t& attestation_signing_key,
                                       const AttestationRecordContext& context,
                                       CertChainPtr* cert_chain_out) {

    // assume the conversion to EVP key correctly encodes the key type such
    // that EVP_PKEY_type(evp_key->type) returns correctly.
    EVP_PKEY_Ptr pkey(EVP_PKEY_new());
    if (!key.InternalToEvp(pkey.get())) {
        return TranslateLastOpenSslError();
    }

    return generate_attestation_from_EVP(
        pkey.get(), key.sw_enforced(), key.hw_enforced(), attest_params, context,
        kCurrentKeymasterVersion, attestation_chain, attestation_signing_key, cert_chain_out);
}


}  // namespace keymaster
