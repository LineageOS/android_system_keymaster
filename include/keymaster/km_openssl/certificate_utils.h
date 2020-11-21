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

#pragma once

#include <hardware/keymaster_defs.h>

#include <keymaster/km_openssl/openssl_utils.h>

#include <openssl/x509v3.h>

namespace keymaster {

keymaster_error_t make_name_from_str(const char name[], X509_NAME_Ptr* name_out);

keymaster_error_t make_name_from_der(const uint8_t* name, size_t length, X509_NAME_Ptr* name_out);

keymaster_error_t get_common_name(X509_NAME* name, UniquePtr<const char[]>* name_out);

keymaster_error_t make_key_usage_extension(bool is_signing_key, bool is_encryption_key,
                                           X509_EXTENSION_Ptr* usage_extension_out);

// Creates a rump certificate structure with serial, subject and issuer names, as well as
// activation and expiry date.
// Callers should pass an empty X509_Ptr and check the return value for KM_ERROR_OK (0) before
// accessing the result.
keymaster_error_t make_cert_rump(const uint32_t serial, const X509_NAME* subject,
                                 const X509_NAME* issuer, const uint64_t activeDateTimeMilliSeconds,
                                 const uint64_t usageExpireDateTimeMilliSeconds,
                                 X509_Ptr* cert_out);

keymaster_error_t make_cert(const EVP_PKEY* evp_pkey, const uint32_t serial,
                            const X509_NAME* subject, const X509_NAME* issuer,
                            const uint64_t activeDateTimeMilliSeconds,
                            const uint64_t usageExpireDateTimeMilliSeconds,
                            const bool is_signing_key, const bool is_encryption_key,
                            X509_Ptr* cert_out);

// Takes a certificate, a signing certificate, and the raw private signing_key.
// Signs the certificate with the latter.
keymaster_error_t sign_cert(X509* certificate, X509* signing_cert,
                            const keymaster_key_blob_t& signing_key);
}  // namespace keymaster
