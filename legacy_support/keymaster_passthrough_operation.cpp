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

#include "keymaster_passthrough_operation.h"
#include <keymaster/android_keymaster_utils.h>
#include <vector>

namespace keymaster {

template <>
keymaster_error_t KeymasterPassthroughOperation<keymaster2_device_t>::Finish(
    const AuthorizationSet& input_params, const Buffer& input, const Buffer& signature,
    AuthorizationSet* output_params, Buffer* output) {
    keymaster_key_param_set_t out_params = {};
    keymaster_blob_t sig{signature.peek_read(), signature.available_read()};
    keymaster_blob_t in{input.peek_read(), input.available_read()};
    keymaster_blob_t out = {};
    keymaster_error_t rc;
    rc = km_device_->finish(km_device_, operation_handle_, &input_params, &in, &sig, &out_params,
                            &out);
    if (rc == KM_ERROR_OK) {
        if (output) output->Reinitialize(out.data, out.data_length);
        if (output_params) output_params->Reinitialize(out_params);
    }
    keymaster_free_param_set(&out_params);
    free(const_cast<uint8_t*>(out.data));
    return rc;
}

}  // namespace keymaster
