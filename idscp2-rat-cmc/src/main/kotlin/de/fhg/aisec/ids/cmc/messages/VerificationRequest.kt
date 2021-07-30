package de.fhg.aisec.ids.cmc.messages

data class VerificationRequest(val type: String, val attestationReport: String, val nonce: String)