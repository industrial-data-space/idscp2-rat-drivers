import com.google.protobuf.gradle.id

plugins {
    alias(libs.plugins.protobuf)
}

tasks.named("spotlessKotlin") {
    dependsOn("generateProto")
    dependsOn("generateTestProto")
}

dependencies {
    implementation(libs.kotlinx.coroutines)
    implementation(libs.bundles.protobuf)
    implementation(libs.bundles.grpc)
    implementation(libs.javax.annotations)
    implementation(libs.jose4j)
    implementation(libs.gson)
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}"
    }
    plugins {
        id("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:${libs.versions.grpc.get()}"
        }
        id("grpckt") {
            artifact = "io.grpc:protoc-gen-grpc-kotlin:${libs.versions.grpcKotlin.get()}:jdk8@jar"
        }
    }
    generateProtoTasks {
        all().forEach {
            it.plugins {
                id("grpc")
                id("grpckt")
            }
        }
    }
}
