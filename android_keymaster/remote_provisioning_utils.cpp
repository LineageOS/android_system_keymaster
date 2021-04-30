/*
 * Copyright 2021 The Android Open Source Project
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

#include "keymaster/cppcose/cppcose.h"
#include <keymaster/logger.h>
#include <keymaster/remote_provisioning_utils.h>

namespace keymaster {

using cppcose::ALGORITHM;
using cppcose::COSE_KEY;
using cppcose::CoseKey;
using cppcose::EC2;
using cppcose::ECDH_ES_HKDF_256;
using cppcose::ES256;
using cppcose::generateCoseMac0Mac;
using cppcose::HMAC_256;
using cppcose::kCoseMac0EntryCount;
using cppcose::kCoseMac0Payload;
using cppcose::kCoseMac0ProtectedParams;
using cppcose::kCoseMac0Tag;
using cppcose::kCoseMac0UnprotectedParams;
using cppcose::KEY_ID;
using cppcose::OCTET_KEY_PAIR;
using cppcose::P256;
using cppcose::verifyAndParseCoseSign1;

// Hard-coded set of acceptable public keys that can act as roots of EEK chains.
inline const std::vector<std::vector<uint8_t>> kAuthorizedEekRoots = {
    {0x5c, 0xea, 0x4b, 0xd2, 0x31, 0x27, 0x15, 0x5e, 0x62, 0x94, 0x70,
     0x53, 0x94, 0x43, 0x0f, 0x9a, 0x89, 0xd5, 0xc5, 0x0f, 0x82, 0x9b,
     0xcd, 0x10, 0xe0, 0x79, 0xef, 0xf3, 0xfa, 0x40, 0xeb, 0x0a},
};

StatusOr<std::pair<std::vector<uint8_t> /* EEK pub */, std::vector<uint8_t> /* EEK ID */>>
validateAndExtractEekPubAndId(bool testMode, const KeymasterBlob& endpointEncryptionCertChain) {
    auto [item, newPos, errMsg] =
        cppbor::parse(endpointEncryptionCertChain.begin(), endpointEncryptionCertChain.end());

    if (!item || !item->asArray()) {
        LOG_E("Error parsing EEK chain: %s", errMsg.c_str());
        return kStatusFailed;
    }

    const cppbor::Array* certArr = item->asArray();
    std::vector<uint8_t> lastPubKey;
    for (int i = 0; i < certArr->size(); ++i) {
        auto cosePubKey =
            verifyAndParseCoseSign1(testMode, certArr->get(i)->asArray(), lastPubKey, {} /* AAD */);
        if (!cosePubKey) {
            LOG_E("Failed to validate EEK chain: %s", cosePubKey.moveMessage().c_str());
            return kStatusInvalidEek;
        }
        lastPubKey = *std::move(cosePubKey);

        // In prod mode the first pubkey should match a well-known Google public key.
        if (!testMode && i == 0 &&
            std::find(kAuthorizedEekRoots.begin(), kAuthorizedEekRoots.end(), lastPubKey) ==
                kAuthorizedEekRoots.end()) {
            LOG_E("Unrecognized root of EEK chain", 0);
            return kStatusInvalidEek;
        }
    }

    auto eek = CoseKey::parseX25519(lastPubKey, true /* requireKid */);
    if (!eek) {
        LOG_E("Failed to get EEK: %s", eek.moveMessage().c_str());
        return kStatusInvalidEek;
    }

    return std::make_pair(eek->getBstrValue(CoseKey::PUBKEY_X).value(),
                          eek->getBstrValue(CoseKey::KEY_ID).value());
}

StatusOr<std::vector<uint8_t> /* pubkeys */>
validateAndExtractPubkeys(bool testMode, uint32_t numKeys, KeymasterBlob* keysToSign,
                          cppcose::HmacSha256Function macFunction) {
    auto pubKeysToMac = cppbor::Array();
    for (int i = 0; i < numKeys; i++) {
        auto [macedKeyItem, _, coseMacErrMsg] =
            cppbor::parse(keysToSign[i].begin(), keysToSign[i].end());
        if (!macedKeyItem || !macedKeyItem->asArray() ||
            macedKeyItem->asArray()->size() != kCoseMac0EntryCount) {
            LOG_E("Invalid COSE_Mac0 structure", 0);
            return kStatusFailed;
        }

        auto protectedParms = macedKeyItem->asArray()->get(kCoseMac0ProtectedParams)->asBstr();
        auto unprotectedParms = macedKeyItem->asArray()->get(kCoseMac0UnprotectedParams)->asMap();
        auto payload = macedKeyItem->asArray()->get(kCoseMac0Payload)->asBstr();
        auto tag = macedKeyItem->asArray()->get(kCoseMac0Tag)->asBstr();
        if (!protectedParms || !unprotectedParms || !payload || !tag) {
            LOG_E("Invalid COSE_Mac0 contents", 0);
            return kStatusFailed;
        }

        auto [protectedMap, __, errMsg] = cppbor::parse(protectedParms);
        if (!protectedMap || !protectedMap->asMap()) {
            LOG_E("Invalid Mac0 protected: %s", errMsg.c_str());
            return kStatusFailed;
        }
        auto& algo = protectedMap->asMap()->get(ALGORITHM);
        if (!algo || !algo->asInt() || algo->asInt()->value() != HMAC_256) {
            LOG_E("Unsupported Mac0 algorithm", 0);
            return kStatusFailed;
        }

        auto pubKey = CoseKey::parse(payload->value(), EC2, ES256, P256);
        if (!pubKey) {
            LOG_E("%s", pubKey.moveMessage().c_str());
            return kStatusFailed;
        }

        bool testKey = static_cast<bool>(pubKey->getMap().get(CoseKey::TEST_KEY));
        if (testMode && !testKey) {
            LOG_E("Production key in test request", 0);
            return kStatusProductionKeyInTestRequest;
        } else if (!testMode && testKey) {
            LOG_E("Test key in production request", 0);
            return kStatusTestKeyInProductionRequest;
        }

        auto macTag = generateCoseMac0Mac(macFunction, {} /* external_aad */, payload->value());
        if (!macTag) {
            LOG_E("%s", macTag.moveMessage().c_str());
            return kStatusInvalidMac;
        }
        if (macTag->size() != tag->value().size() ||
            CRYPTO_memcmp(macTag->data(), tag->value().data(), macTag->size()) != 0) {
            LOG_E("MAC tag mismatch", 0);
            return kStatusInvalidMac;
        }

        pubKeysToMac.add(pubKey->moveMap());
    }

    return pubKeysToMac.encode();
}

cppbor::Array buildCertReqRecipients(const std::vector<uint8_t>& pubkey,
                                     const std::vector<uint8_t>& kid) {
    return cppbor::Array()           // Array of recipients
        .add(cppbor::Array()         // Recipient
                 .add(cppbor::Map()  // Protected
                          .add(ALGORITHM, ECDH_ES_HKDF_256)
                          .canonicalize()
                          .encode())
                 .add(cppbor::Map()  // Unprotected
                          .add(COSE_KEY, cppbor::Map()
                                             .add(CoseKey::KEY_TYPE, OCTET_KEY_PAIR)
                                             .add(CoseKey::CURVE, cppcose::X25519)
                                             .add(CoseKey::PUBKEY_X, pubkey)
                                             .canonicalize())
                          .add(KEY_ID, kid)
                          .canonicalize())
                 .add(cppbor::Null()));  // No ciphertext
}

}  // namespace keymaster
