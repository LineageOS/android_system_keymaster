/*
 * Copyright 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <keymaster/km_openssl/aes_key.h>

#include <utility>

#include <assert.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include "aes_operation.h"

namespace keymaster {

static AesOperationFactory encrypt_factory(KM_PURPOSE_ENCRYPT);
static AesOperationFactory decrypt_factory(KM_PURPOSE_DECRYPT);

OperationFactory* AesKeyFactory::GetOperationFactory(keymaster_purpose_t purpose) const {
    switch (purpose) {
    case KM_PURPOSE_ENCRYPT:
        return &encrypt_factory;
    case KM_PURPOSE_DECRYPT:
        return &decrypt_factory;
    default:
        return nullptr;
    }
}

keymaster_error_t AesKeyFactory::LoadKey(KeymasterKeyBlob&& key_material,
                                         const AuthorizationSet& /* additional_params */,
                                         AuthorizationSet&& hw_enforced,
                                         AuthorizationSet&& sw_enforced,
                                         UniquePtr<Key>* key) const {
    if (!key) return KM_ERROR_OUTPUT_PARAMETER_NULL;

    uint32_t min_mac_length = 0;
    if (hw_enforced.Contains(TAG_BLOCK_MODE, KM_MODE_GCM) ||
        sw_enforced.Contains(TAG_BLOCK_MODE, KM_MODE_GCM)) {

        if (!hw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length) &&
            !sw_enforced.GetTagValue(TAG_MIN_MAC_LENGTH, &min_mac_length)) {

            LOG_E("AES-GCM key must have KM_TAG_MIN_MAC_LENGTH");
            return KM_ERROR_INVALID_KEY_BLOB;
        }
    }

    keymaster_error_t error = KM_ERROR_OK;
    key->reset(new (std::nothrow)
                   AesKey(std::move(key_material), std::move(hw_enforced), std::move(sw_enforced),
                          this));
    if (!key->get()) error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
    return error;
}

keymaster_error_t AesKeyFactory::validate_algorithm_specific_new_key_params(
    const AuthorizationSet& key_description) const {
    if (key_description.Contains(TAG_BLOCK_MODE, KM_MODE_GCM)) {
        uint32_t min_tag_length;
        if (!key_description.GetTagValue(TAG_MIN_MAC_LENGTH, &min_tag_length))
            return KM_ERROR_MISSING_MIN_MAC_LENGTH;

        if (min_tag_length % 8 != 0) return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;

        if (min_tag_length < kMinGcmTagLength || min_tag_length > kMaxGcmTagLength)
            return KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH;
    } else {
        // Not GCM
        if (key_description.find(TAG_MIN_MAC_LENGTH) != -1) {
            LOG_W("KM_TAG_MIN_MAC_LENGTH found for non AES-GCM key");
            return KM_ERROR_INVALID_TAG;
        }
    }

    return KM_ERROR_OK;
}

}  // namespace keymaster
