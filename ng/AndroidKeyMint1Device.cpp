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

#define LOG_TAG "android.hardware.keymint@1.0-impl"
#include <log/log.h>

#include "include/AndroidKeyMint1Device.h"

#include "KeyMintAidlUtils.h"
#include "include/AndroidKeyMint1Operation.h"

#include <aidl/android/hardware/keymint/ErrorCode.h>

#include <keymaster/android_keymaster.h>
#include <keymaster/contexts/pure_soft_keymaster_context.h>
#include <keymaster/keymaster_configuration.h>

namespace aidl {
namespace android {
namespace hardware {
namespace keymint {
namespace V1_0 {

using ::aidl::android::hardware::keymint::ErrorCode;
using ::aidl::android::hardware::keymint::HardwareAuthToken;
using ::aidl::android::hardware::keymint::VerificationToken;

using namespace ::keymaster;

constexpr size_t kOperationTableSize = 16;

AndroidKeyMint1Device::AndroidKeyMint1Device(SecurityLevel securityLevel)
    : impl_(new ::keymaster::AndroidKeymaster(
          [&]() -> auto {
              auto context = new PureSoftKeymasterContext(
                  static_cast<keymaster_security_level_t>(securityLevel));
              context->SetSystemVersion(::keymaster::GetOsVersion(),
                                        ::keymaster::GetOsPatchlevel());
              return context;
          }(),
          kOperationTableSize)),
      securityLevel_(securityLevel) {}

AndroidKeyMint1Device::~AndroidKeyMint1Device() {}

ScopedAStatus AndroidKeyMint1Device::getHardwareInfo(KeyMintHardwareInfo* info) {
    info->versionNumber = 1;
    info->securityLevel = securityLevel_;
    info->keyMintName = "FakeKeyMintDevice";
    info->keyMintAuthorName = "Google";

    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::verifyAuthorization(int64_t challenge,                   //
                                                         const HardwareAuthToken& authToken,  //
                                                         VerificationToken* verificationToken) {

    VerifyAuthorizationRequest request;
    request.challenge = static_cast<uint64_t>(challenge);
    request.auth_token.challenge = authToken.challenge;
    request.auth_token.user_id = authToken.userId;
    request.auth_token.authenticator_id = authToken.authenticatorId;
    request.auth_token.authenticator_type = legacy_enum_conversion(authToken.authenticatorType);

    // TODO(seleneh) b/162481130 remove the casting once uint is supported in aidl
    request.auth_token.timestamp = static_cast<uint64_t>(authToken.timestamp.milliSeconds);
    KeymasterBlob mac(authToken.mac.data(), authToken.mac.size());
    request.auth_token.mac = KeymasterBlob(authToken.mac.data(), authToken.mac.size());

    auto response = impl_->VerifyAuthorization(request);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    verificationToken->challenge = response.token.challenge;
    verificationToken->timestamp.milliSeconds = static_cast<int64_t>(response.token.timestamp);
    verificationToken->securityLevel = legacy_enum_conversion(response.token.security_level);
    verificationToken->mac = kmBlob2vector(response.token.mac);

    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::addRngEntropy(const vector<uint8_t>& data) {
    if (data.size() == 0) {
        return ScopedAStatus::ok();
    }

    AddEntropyRequest request;
    request.random_data.Reinitialize(data.data(), data.size());

    AddEntropyResponse response;
    impl_->AddRngEntropy(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus AndroidKeyMint1Device::generateKey(const vector<KeyParameter>& keyParams,
                                                 ByteArray* generatedKeyBlob,
                                                 KeyCharacteristics* generatedKeyCharacteristics,
                                                 vector<Certificate>* /* certChain */) {

    GenerateKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(keyParams));

    GenerateKeyResponse response;
    impl_->GenerateKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        // Note a key difference between this current aidl and previous hal, is
        // that hal returns void where as aidl returns the error status.  If
        // aidl returns error, then aidl will not return any change you may make
        // to the out parameters.  This is quite different from hal where all
        // output variable can be modified due to hal returning void.
        //
        // So the caller need to be aware not to expect aidl functions to clear
        // the output variables for you in case of error.  If you left some
        // wrong data set in the out parameters, they will stay there.
        return kmError2ScopedAStatus(response.error);
    }

    generatedKeyBlob->data = kmBlob2vector(response.key_blob);
    generatedKeyCharacteristics->hardwareEnforced = kmParamSet2Aidl(response.enforced);
    generatedKeyCharacteristics->softwareEnforced = kmParamSet2Aidl(response.unenforced);

    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::importKey(const vector<KeyParameter>& keyParams,
                                               KeyFormat keyFormat, const vector<uint8_t>& keyData,
                                               ByteArray* importedKeyBlob,
                                               KeyCharacteristics* importedKeyCharacteristics,
                                               vector<Certificate>* /* certChain */) {

    ImportKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(keyParams));
    request.key_format = legacy_enum_conversion(keyFormat);
    request.SetKeyMaterial(keyData.data(), keyData.size());

    ImportKeyResponse response;
    impl_->ImportKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    importedKeyBlob->data = kmBlob2vector(response.key_blob);
    importedKeyCharacteristics->hardwareEnforced = kmParamSet2Aidl(response.enforced);
    importedKeyCharacteristics->softwareEnforced = kmParamSet2Aidl(response.unenforced);

    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::importWrappedKey(
    const vector<uint8_t>& wrappedKeyData, const vector<uint8_t>& wrappingKeyBlob,
    const vector<uint8_t>& maskingKey, const vector<KeyParameter>& unwrappingParams,
    int64_t passwordSid, int64_t biometricSid, ByteArray* importedKeyBlob,
    KeyCharacteristics* importedKeyCharacteristics) {

    ImportWrappedKeyRequest request;
    request.SetWrappedMaterial(wrappedKeyData.data(), wrappedKeyData.size());
    request.SetWrappingMaterial(wrappingKeyBlob.data(), wrappingKeyBlob.size());
    request.SetMaskingKeyMaterial(maskingKey.data(), maskingKey.size());
    request.additional_params.Reinitialize(KmParamSet(unwrappingParams));
    request.password_sid = static_cast<uint64_t>(passwordSid);
    request.biometric_sid = static_cast<uint64_t>(biometricSid);

    ImportWrappedKeyResponse response;
    impl_->ImportWrappedKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    importedKeyBlob->data = kmBlob2vector(response.key_blob);
    importedKeyCharacteristics->hardwareEnforced = kmParamSet2Aidl(response.enforced);
    importedKeyCharacteristics->softwareEnforced = kmParamSet2Aidl(response.unenforced);

    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::upgradeKey(const vector<uint8_t>& keyBlobToUpgrade,
                                                const vector<KeyParameter>& upgradeParams,
                                                vector<uint8_t>* keyBlob) {

    UpgradeKeyRequest request;
    request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
    request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

    UpgradeKeyResponse response;
    impl_->UpgradeKey(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    *keyBlob = kmBlob2vector(response.upgraded_key);
    return ScopedAStatus::ok();
}

ScopedAStatus AndroidKeyMint1Device::deleteKey(const vector<uint8_t>& keyBlob) {
    DeleteKeyRequest request;
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    DeleteKeyResponse response;
    impl_->DeleteKey(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus AndroidKeyMint1Device::deleteAllKeys() {
    // There's nothing to be done to delete software key blobs.
    DeleteAllKeysRequest request;
    DeleteAllKeysResponse response;
    impl_->DeleteAllKeys(request, &response);

    return kmError2ScopedAStatus(response.error);
}

ScopedAStatus AndroidKeyMint1Device::destroyAttestationIds() {
    return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);
}

ScopedAStatus AndroidKeyMint1Device::begin(KeyPurpose purpose, const vector<uint8_t>& keyBlob,
                                           const vector<KeyParameter>& params,
                                           const HardwareAuthToken& authToken,
                                           BeginResult* result) {

    BeginOperationRequest request;
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    request.additional_params.Reinitialize(KmParamSet(params));

    vector<uint8_t> vector_token = authToken2AidlVec(authToken);
    request.additional_params.push_back(
        TAG_AUTH_TOKEN, reinterpret_cast<uint8_t*>(vector_token.data()), vector_token.size());

    BeginOperationResponse response;
    impl_->BeginOperation(request, &response);

    if (response.error != KM_ERROR_OK) {
        return kmError2ScopedAStatus(response.error);
    }

    result->params = kmParamSet2Aidl(response.output_params);
    result->challenge = response.op_handle;
    result->operation =
        ndk::SharedRefBase::make<AndroidKeyMint1Operation>(impl_, response.op_handle);
    return ScopedAStatus::ok();
}

IKeyMintDevice* CreateKeyMintDevice(SecurityLevel securityLevel) {

    return ::new AndroidKeyMint1Device(securityLevel);
}

}  // namespace V1_0
}  // namespace keymint
}  // namespace hardware
}  // namespace android
}  // namespace aidl
