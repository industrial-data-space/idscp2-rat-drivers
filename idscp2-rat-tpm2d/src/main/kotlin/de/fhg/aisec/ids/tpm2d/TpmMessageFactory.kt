/*-
 * ========================LICENSE_START=================================
 * idscp2-rat-tpm2d
 * %%
 * Copyright (C) 2021 Fraunhofer AISEC
 * %%
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
 * =========================LICENSE_END==================================
 */
package de.fhg.aisec.ids.tpm2d

import com.google.protobuf.ByteString
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.IdsAttestationType
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.RemoteToTpm
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmChallenge
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmMessage
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmResponse
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmResult
import de.fhg.aisec.ids.tpm2d.messages.TpmAttestation.TpmToRemote

/**
 * A message factory for creating TPM2d RAT messages
 *
 * @author Leon Beckmann (leon.beckmann@aisec.fraunhofer.de)
 */
object TpmMessageFactory {
    fun getAttestationChallengeMessage(
        nonce: ByteArray,
        aType: IdsAttestationType,
        pcrIndices: Int
    ): TpmMessage {
        return TpmMessage.newBuilder().setRatChallenge(
            TpmChallenge.newBuilder()
                .setAtype(aType)
                .setNonce(ByteString.copyFrom(nonce))
                .setPcrIndices(pcrIndices)
                .build()
        ).build()
    }

    fun getAttestationResponseMessage(
        response: TpmToRemote
    ): TpmMessage {
        return TpmMessage.newBuilder().setRatResponse(
            TpmResponse.newBuilder()
                .setAtype(response.atype)
                .setHashAlg(response.halg.name)
                .setQuoted(response.quoted)
                .setSignature(response.signature)
                .addAllPcrValues(response.pcrValuesList)
                .setCertificate(response.certificate)
                .build()
        ).build()
    }

    fun getAttestationResultMessage(
        result: Boolean
    ): TpmMessage {
        return TpmMessage.newBuilder().setRatResult(
            TpmResult.newBuilder()
                .setResult(result)
                .build()
        ).build()
    }

    fun getRemoteToTPM2dMessage(
        aType: IdsAttestationType,
        hash: ByteArray,
        pcrIndices: Int
    ): RemoteToTpm {
        return RemoteToTpm.newBuilder()
            .setAtype(aType)
            .setQualifyingData(ByteString.copyFrom(hash))
            .setCode(RemoteToTpm.Code.ATTESTATION_REQ)
            .setPcrs(pcrIndices)
            .build()
    }
}
