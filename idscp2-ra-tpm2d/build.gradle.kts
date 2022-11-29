plugins {
    alias(libs.plugins.protobuf)
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}"
    }
}

tasks.named("spotlessKotlin") {
    dependsOn(tasks.named("generateProto"))
    dependsOn(tasks.named("generateTestProto"))
}

val api by configurations
val testImplementation by configurations

dependencies {
    api(libs.protobuf.java)
    implementation(libs.tss)
    implementation(libs.jose4j)

    testImplementation(libs.idscp2.core)
    testImplementation(libs.bundles.testing)
}
