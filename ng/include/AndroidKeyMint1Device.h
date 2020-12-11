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

#pragma once

#include <aidl/android/hardware/keymint/BnKeyMintDevice.h>
#include <aidl/android/hardware/keymint/BnKeyMintOperation.h>
#include <aidl/android/hardware/keymint/HardwareAuthToken.h>

namespace keymaster {
class AndroidKeymaster;
}

namespace aidl {
namespace android {
namespace hardware {
namespace keymint {

namespace V1_0 {

using ::aidl::android::hardware::keymint::Certificate;
using ::aidl::android::hardware::keymint::HardwareAuthToken;
using ::aidl::android::hardware::keymint::IKeyMintOperation;
using ::aidl::android::hardware::keymint::KeyCharacteristics;
using ::aidl::android::hardware::keymint::KeyFormat;
using ::aidl::android::hardware::keymint::KeyMintHardwareInfo;
using ::aidl::android::hardware::keymint::KeyParameter;
using ::aidl::android::hardware::keymint::KeyPurpose;
using ::aidl::android::hardware::keymint::VerificationToken;

using ::ndk::ScopedAStatus;
using std::shared_ptr;
using std::vector;

class AndroidKeyMint1Device : public BnKeyMintDevice {
  public:
    explicit AndroidKeyMint1Device(SecurityLevel securityLevel);
    virtual ~AndroidKeyMint1Device();

    ScopedAStatus getHardwareInfo(KeyMintHardwareInfo* info) override;

    ScopedAStatus verifyAuthorization(int64_t challenge, const HardwareAuthToken& token,
                                      VerificationToken* verificationToken) override;

    ScopedAStatus addRngEntropy(const vector<uint8_t>& data) override;

    ScopedAStatus generateKey(const vector<KeyParameter>& keyParams, ByteArray* generatedKeyBlob,
                              KeyCharacteristics* generatedKeyCharacteristics,
                              vector<Certificate>* certChain) override;

    ScopedAStatus importKey(const vector<KeyParameter>& keyParams, KeyFormat keyFormat,
                            const vector<uint8_t>& keyData, ByteArray* importedKeyBlob,
                            KeyCharacteristics* importedKeyCharacteristics,
                            vector<Certificate>* certChain) override;

    ScopedAStatus importWrappedKey(const vector<uint8_t>& wrappedKeyData,
                                   const vector<uint8_t>& wrappingKeyBlob,
                                   const vector<uint8_t>& maskingKey,
                                   const vector<KeyParameter>& unwrappingParams,
                                   int64_t passwordSid, int64_t biometricSid,
                                   ByteArray* importedKeyBlob,
                                   KeyCharacteristics* importedKeyCharacteristics) override;

    ScopedAStatus upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                             const vector<KeyParameter>& upgradeParams,
                             vector<uint8_t>* keyBlob) override;

    ScopedAStatus deleteKey(const vector<uint8_t>& keyBlob) override;
    ScopedAStatus deleteAllKeys() override;
    ScopedAStatus destroyAttestationIds() override;

    ScopedAStatus begin(KeyPurpose purpose, const vector<uint8_t>& keyBlob,
                        const vector<KeyParameter>& params, const HardwareAuthToken& authToken,
                        BeginResult* result) override;

  protected:
    std::shared_ptr<::keymaster::AndroidKeymaster> impl_;
    SecurityLevel securityLevel_;
};

IKeyMintDevice* CreateKeyMintDevice(SecurityLevel securityLevel);

}  // namespace V1_0
}  // namespace keymint
}  // namespace hardware
}  // namespace android
}  // namespace aidl
