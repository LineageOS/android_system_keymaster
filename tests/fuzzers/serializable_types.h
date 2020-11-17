/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/serializable.h>

namespace keymaster {
enum class SerializableType : uint32_t {
    SUPPORTED_ALGORITHMS_REQUEST,
    SUPPORTED_BY_ALGORITHM_REQUEST,
    SUPPORTED_IMPORT_FORMATS_REQUEST,
    SUPPORTED_EXPORT_FORMATS_REQUEST,
    SUPPORTED_BY_ALGORITHM_AND_PURPOSE_REQUEST,
    SUPPORTED_BLOCK_MODES_REQUEST,
    SUPPORTED_PADDING_MODES_REQUEST,
    SUPPORTED_DIGESTS_REQUEST,
    SUPPORTED_ALGORITHMS_RESPONSE,
    SUPPORTED_BLOCK_MODES_RESPONSE,
    SUPPORTED_PADDING_MODES_RESPONSE,
    SUPPORTED_DIGESTS_RESPONSE,
    SUPPORTED_IMPORT_FORMATS_RESPONSE,
    SUPPORTED_EXPORT_FORMATS_RESPONSE,
    GENERATE_KEY_REQUEST,
    GENERATE_KEY_RESPONSE,
    GET_KEY_CHARACTERISTICS_REQUEST,
    GET_KEY_CHARACTERISTICS_RESPONSE,
    BEGIN_OPERATION_REQUEST,
    BEGIN_OPERATION_RESPONSE,
    UPDATE_OPERATION_REQUEST,
    UPDATE_OPERATION_RESPONSE,
    FINISH_OPERATION_REQUEST,
    FINISH_OPERATION_RESPONSE,
    ABORT_OPERATION_REQUEST,
    ABORT_OPERATION_RESPONSE,
    ADD_ENTROPY_REQUEST,
    ADD_ENTROPY_RESPONSE,
    IMPORT_KEY_REQUEST,
    IMPORT_KEY_RESPONSE,
    EXPORT_KEY_REQUEST,
    EXPORT_KEY_RESPONSE,
    DELETE_KEY_REQUEST,
    DELETE_KEY_RESPONSE,
    DELETE_ALL_KEYS_REQUEST,
    DELETE_ALL_KEYS_RESPONSE,
    GET_VERSION_REQUEST,
    GET_VERSION_RESPONSE,
    ATTEST_KEY_REQUEST,
    ATTEST_KEY_RESPONSE,
    UPGRADE_KEY_REQUEST,
    UPGRADE_KEY_RESPONSE,
    CONFIGURE_REQUEST,
    CONFIGURE_RESPONSE,
    HMAC_SHARING_PARAMETERS,
    HMAC_SHARING_PARAMETERS_ARRAY,
    GET_HMAC_SHARING_PARAMETERS_RESPONSE,
    COMPUTE_SHARED_HMAC_REQUEST,
    COMPUTE_SHARED_HMAC_RESPONSE,
    IMPORT_WRAPPED_KEY_REQUEST,
    IMPORT_WRAPPED_KEY_RESPONSE,
    HARDWARE_AUTH_TOKEN,
    VERIFICATION_TOKEN,
    VERIFY_AUTHORIZATION_REQUEST,
    VERIFY_AUTHORIZATION_RESPONSE,
    DEVICE_LOCKED_REQUEST,
    BUFFER,
    // Libfuzzer needs this to always be the last value
    kMaxValue = BUFFER
};

std::unique_ptr<Serializable> getSerializable(SerializableType serType) {
    switch (serType) {
    case SerializableType::SUPPORTED_ALGORITHMS_REQUEST:
        return std::make_unique<SupportedAlgorithmsRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_BY_ALGORITHM_REQUEST:
        return std::make_unique<SupportedByAlgorithmRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_IMPORT_FORMATS_REQUEST:
        return std::make_unique<SupportedImportFormatsRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_EXPORT_FORMATS_REQUEST:
        return std::make_unique<SupportedExportFormatsRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_BY_ALGORITHM_AND_PURPOSE_REQUEST:
        return std::make_unique<SupportedByAlgorithmAndPurposeRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_BLOCK_MODES_REQUEST:
        return std::make_unique<SupportedBlockModesRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_PADDING_MODES_REQUEST:
        return std::make_unique<SupportedPaddingModesRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_DIGESTS_REQUEST:
        return std::make_unique<SupportedDigestsRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_ALGORITHMS_RESPONSE:
        return std::make_unique<SupportedAlgorithmsResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_BLOCK_MODES_RESPONSE:
        return std::make_unique<SupportedBlockModesResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_PADDING_MODES_RESPONSE:
        return std::make_unique<SupportedPaddingModesResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_DIGESTS_RESPONSE:
        return std::make_unique<SupportedDigestsResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_IMPORT_FORMATS_RESPONSE:
        return std::make_unique<SupportedImportFormatsResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::SUPPORTED_EXPORT_FORMATS_RESPONSE:
        return std::make_unique<SupportedExportFormatsResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::GENERATE_KEY_REQUEST:
        return std::make_unique<GenerateKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::GENERATE_KEY_RESPONSE:
        return std::make_unique<GenerateKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::GET_KEY_CHARACTERISTICS_REQUEST:
        return std::make_unique<GetKeyCharacteristicsRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::GET_KEY_CHARACTERISTICS_RESPONSE:
        return std::make_unique<GetKeyCharacteristicsResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::BEGIN_OPERATION_REQUEST:
        return std::make_unique<BeginOperationRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::BEGIN_OPERATION_RESPONSE:
        return std::make_unique<BeginOperationResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::UPDATE_OPERATION_REQUEST:
        return std::make_unique<UpdateOperationRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::UPDATE_OPERATION_RESPONSE:
        return std::make_unique<UpdateOperationResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::FINISH_OPERATION_REQUEST:
        return std::make_unique<FinishOperationRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::FINISH_OPERATION_RESPONSE:
        return std::make_unique<FinishOperationResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::ABORT_OPERATION_REQUEST:
        return std::make_unique<AbortOperationRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::ABORT_OPERATION_RESPONSE:
        return std::make_unique<AbortOperationResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::ADD_ENTROPY_REQUEST:
        return std::make_unique<AddEntropyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::ADD_ENTROPY_RESPONSE:
        return std::make_unique<AddEntropyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::IMPORT_KEY_REQUEST:
        return std::make_unique<ImportKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::IMPORT_KEY_RESPONSE:
        return std::make_unique<ImportKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::EXPORT_KEY_REQUEST:
        return std::make_unique<ExportKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::EXPORT_KEY_RESPONSE:
        return std::make_unique<ExportKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::DELETE_KEY_REQUEST:
        return std::make_unique<DeleteKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::DELETE_KEY_RESPONSE:
        return std::make_unique<DeleteKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::DELETE_ALL_KEYS_REQUEST:
        return std::make_unique<DeleteAllKeysRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::DELETE_ALL_KEYS_RESPONSE:
        return std::make_unique<DeleteAllKeysResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::GET_VERSION_REQUEST:
        // Not versionable
        return std::make_unique<GetVersionRequest>();
    case SerializableType::GET_VERSION_RESPONSE:
        // Not versionable
        return std::make_unique<GetVersionResponse>();
    case SerializableType::ATTEST_KEY_REQUEST:
        return std::make_unique<AttestKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::ATTEST_KEY_RESPONSE:
        return std::make_unique<AttestKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::UPGRADE_KEY_REQUEST:
        return std::make_unique<UpgradeKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::UPGRADE_KEY_RESPONSE:
        return std::make_unique<UpgradeKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::CONFIGURE_REQUEST:
        return std::make_unique<ConfigureRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::CONFIGURE_RESPONSE:
        return std::make_unique<ConfigureResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::DEVICE_LOCKED_REQUEST:
        return std::make_unique<DeviceLockedRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::GET_HMAC_SHARING_PARAMETERS_RESPONSE:
        return std::make_unique<GetHmacSharingParametersResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::COMPUTE_SHARED_HMAC_REQUEST:
        return std::make_unique<ComputeSharedHmacRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::COMPUTE_SHARED_HMAC_RESPONSE:
        return std::make_unique<ComputeSharedHmacResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::IMPORT_WRAPPED_KEY_REQUEST:
        return std::make_unique<ImportWrappedKeyRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::IMPORT_WRAPPED_KEY_RESPONSE:
        return std::make_unique<ImportWrappedKeyResponse>(MAX_MESSAGE_VERSION);
    case SerializableType::VERIFY_AUTHORIZATION_REQUEST:
        return std::make_unique<VerifyAuthorizationRequest>(MAX_MESSAGE_VERSION);
    case SerializableType::VERIFY_AUTHORIZATION_RESPONSE:
        return std::make_unique<VerifyAuthorizationResponse>(MAX_MESSAGE_VERSION);

    // These are not messages, and expect an empty constructor.
    case SerializableType::HMAC_SHARING_PARAMETERS:
        return std::make_unique<HmacSharingParameters>();
    case SerializableType::HMAC_SHARING_PARAMETERS_ARRAY:
        return std::make_unique<HmacSharingParametersArray>();
    case SerializableType::HARDWARE_AUTH_TOKEN:
        return std::make_unique<HardwareAuthToken>();
    case SerializableType::VERIFICATION_TOKEN:
        return std::make_unique<VerificationToken>();
    case SerializableType::BUFFER:
    default:
        return std::make_unique<Buffer>();
    }
}
}  // namespace keymaster
