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

#include <memory>

#include <keymaster/serializable.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "serializable_types.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    std::unique_ptr<keymaster::Serializable> serializable =
        keymaster::getSerializable(fdp.ConsumeEnum<keymaster::SerializableType>());

    std::vector<uint8_t> in_buf = fdp.ConsumeRemainingBytes<uint8_t>();

    // Now attempt to populate the object by deserializing the data. This will likely fail, but
    // shouldn't crash.
    const uint8_t* data_ptr = in_buf.data();
    serializable->Deserialize(&data_ptr, data_ptr + in_buf.size());

    return 0;
}
