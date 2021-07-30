package de.fhg.aisec.ids.cmc.messages

data class VerificationRequest(val type: String, val attestationReport: Map<String, Any>, val nonce: String)