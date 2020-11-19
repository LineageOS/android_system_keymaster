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

namespace keymaster {

/**
 * Version enumerates the list of Keymaster/KeyMint versions that we may support.  As old
 * versions are deprecated and removed they should be removed from this enum, which will make it
 * possible to easily find the version-dependent code and remove dead branches.
 *
 * The enum values are a bit odd.  They correspond to the Keymaster/KeyMint versions in
 * attestations.
 */
enum class KmVersion {
    KEYMASTER_1 = 1,
    KEYMASTER_2 = 2,
    KEYMASTER_3 = 3,
    KEYMASTER_4 = 4,
    KEYMASTER_4_1 = 41,
    KEYMINT_1 = 100,
};

};  // namespace keymaster
