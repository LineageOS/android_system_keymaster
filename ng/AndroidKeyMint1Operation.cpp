/*
 *
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

#define LOG_TAG "android.hardware.keymint@1.0-impl"
#include <log/log.h>

#include "include/AndroidKeyMint1Operation.h"

#include "KeyMintAidlUtils.h"
#include <aidl/android/hardware/keymint/ErrorCode.h>
#include <keymaster/android_keymaster.h>

namespace aidl {
namespace android {
namespace hardware {
namespace keymint {
namespace V1_0 {

using ::aidl::android::hardware::keymint::ErrorCode;

using ::keymaster::AbortOperationRequest;
using ::keymaster::AbortOperationResponse;
using ::keymaster::FinishOperationRequest;
using ::keymaster::FinishOperationResponse;
using ::keymaster::UpdateOperationRequest;
using ::keymaster::UpdateOperationResponse;

AndroidKeyMint1Operation::AndroidKeyMint1Operation(
    const shared_ptr<::keymaster::AndroidKeymaster> implementation,
    keymaster_operation_handle_t opHandle)
    : impl_(std::move(implementation)), opHandle_(opHandle) {}

AndroidKeyMint1Operation::~AndroidKeyMint1Operation() {
    if (opHandle_ != 0) {
        abort();
    }
}

ScopedAStatus AndroidKeyMint1Operation::update(const optional<KeyParameterArray>& params,
                                               const optional<vector<uint8_t>>& input,
                                               const optional<HardwareAuthToken>& /* authToken */,
                                               const optional<VerificationToken>&
                                               /* verificationToken */,
                                               optional<KeyParameterArray>* updatedParams,
                                               optional<ByteArray>* output,
                                               int32_t* inputConsumed) {
    if (!updatedParams || !output || !inputConsumed) {
        return kmError2ScopedAStatus(KM_ERROR_OUTPUT_PARAMETER_NULL);
    }

    UpdateOperationRequest request;
    request.op_handle = opHandle_;
    if (input) {
        request.input.Reinitialize(input->data(), input->size());
    }

    if (params) {
        request.additional_params.Reinitialize(KmParamSet(params->params));
    }

    UpdateOperationResponse response;
    impl_->UpdateOperation(request, &response);

    *inputConsumed = 0;
    if (response.error == KM_ERROR_OK) {
        *inputConsumed = response.input_consumed;

        updatedParams->emplace();
        (*updatedParams)->params = kmParamSet2Aidl(response.output_params);

        output->emplace();
        (*output)->data = kmBuffer2vector(response.output);

        return ScopedAStatus::ok();
    }

    opHandle_ = 0;
    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus AndroidKeyMint1Operation::finish(const optional<KeyParameterArray>& params,
                                               const optional<vector<uint8_t>>& input,
                                               const optional<vector<uint8_t>>& signature,
                                               const optional<HardwareAuthToken>& /* authToken */,
                                               const optional<VerificationToken>&
                                               /* verificationToken */,
                                               optional<KeyParameterArray>* updatedParams,
                                               vector<uint8_t>* output) {

    if (!updatedParams || !output) {
        return ScopedAStatus(AStatus_fromServiceSpecificError(
            static_cast<int32_t>(ErrorCode::OUTPUT_PARAMETER_NULL)));
    }

    FinishOperationRequest request;
    request.op_handle = opHandle_;

    if (input) {
        request.input.Reinitialize(input->data(), input->size());
    }

    if (signature) {
        request.signature.Reinitialize(signature->data(), signature->size());
    }

    if (params) {
        request.additional_params.Reinitialize(KmParamSet(params->params));
    }

    FinishOperationResponse response;
    impl_->FinishOperation(request, &response);
    opHandle_ = 0;

    if (response.error == KM_ERROR_OK) {
        updatedParams->emplace();
        (*updatedParams)->params = kmParamSet2Aidl(response.output_params);

        *output = kmBuffer2vector(response.output);
        return ScopedAStatus::ok();
    }

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus AndroidKeyMint1Operation::abort() {
    AbortOperationRequest request;
    request.op_handle = opHandle_;

    AbortOperationResponse response;
    impl_->AbortOperation(request, &response);
    opHandle_ = 0;

    return kmError2ScopedAStatus(response.error);
}

}  // namespace V1_0
}  // namespace keymint
}  // namespace hardware
}  // namespace android
}  // namespace aidl
