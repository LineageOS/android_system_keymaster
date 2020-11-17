/*
 **
 ** Copyright 2020, The Android Open Source Project
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

#ifndef android_hardware_keymint_V1_0_AndroidKeyMint1Operation_H_
#define android_hardware_keymint_V1_0_AndroidKeyMint1Operation_H_

#include <aidl/android/hardware/keymint/BnKeyMintOperation.h>

#include <hardware/keymaster_defs.h>

namespace keymaster {
class AndroidKeymaster;
}

namespace aidl {
namespace android {
namespace hardware {
namespace keymint {

namespace V1_0 {

using ::aidl::android::hardware::keymint::HardwareAuthToken;
using ::aidl::android::hardware::keymint::KeyParameterArray;
using ::aidl::android::hardware::keymint::VerificationToken;

using ::ndk::ScopedAStatus;
using std::optional;
using std::shared_ptr;
using std::string;
using std::vector;

class AndroidKeyMint1Operation : public BnKeyMintOperation {
  public:
    explicit AndroidKeyMint1Operation(
        const shared_ptr<::keymaster::AndroidKeymaster> implementation,
        keymaster_operation_handle_t opHandle);

    AndroidKeyMint1Operation() = delete;

    virtual ~AndroidKeyMint1Operation();

    ScopedAStatus update(const optional<KeyParameterArray>& params,
                         const optional<vector<uint8_t>>& input,
                         const optional<HardwareAuthToken>& authToken,
                         const optional<VerificationToken>& verificationToken,
                         optional<KeyParameterArray>* updatedParams, optional<ByteArray>* output,
                         int32_t* inputConsumed) override;

    ScopedAStatus finish(const optional<KeyParameterArray>& params,     //
                         const optional<vector<uint8_t>>& input,        //
                         const optional<vector<uint8_t>>& signature,    //
                         const optional<HardwareAuthToken>& authToken,  //
                         const optional<VerificationToken>& verificationToken,
                         optional<KeyParameterArray>* resultParams,  //
                         vector<uint8_t>* output) override;

    ScopedAStatus abort() override;

  protected:
    std::shared_ptr<::keymaster::AndroidKeymaster> impl_;
    keymaster_operation_handle_t opHandle_;
};

}  // namespace V1_0
}  // namespace keymint
}  // namespace hardware
}  // namespace android
}  // namespace aidl

#endif  // android_hardware_keymint_V1_0_AndroidKeyMint1Operation_H_
