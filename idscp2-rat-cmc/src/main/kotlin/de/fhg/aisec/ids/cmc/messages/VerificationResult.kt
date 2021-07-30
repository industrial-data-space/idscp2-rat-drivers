package de.fhg.aisec.ids.cmc.messages

data class VerificationResult(
    val type: String,
    val raSuccessful: Boolean,
    val certificationLevel: Int,
    val log: Array<String>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as VerificationResult

        if (type != other.type) return false
        if (raSuccessful != other.raSuccessful) return false
        if (certificationLevel != other.certificationLevel) return false
        if (!log.contentEquals(other.log)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + raSuccessful.hashCode()
        result = 31 * result + certificationLevel
        result = 31 * result + log.contentHashCode()
        return result
    }
}