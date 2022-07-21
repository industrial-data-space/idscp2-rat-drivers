import com.google.protobuf.gradle.*
import org.gradle.plugins.ide.idea.model.IdeaModel

val versions = mapOf(
    "annotations" to "1.3.2",
    "jose4j" to "0.7.12",
)

apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

tasks.named("spotlessKotlin") {
    dependsOn("generateProto")
    dependsOn("generateTestProto")
}

dependencies {
    implementation("com.google.protobuf", "protobuf-java", "${rootProject.ext["protobufVersion"]}")
    implementation("io.grpc", "grpc-protobuf", "${rootProject.ext["grpcVersion"]}")
    implementation("io.grpc", "grpc-stub", "${rootProject.ext["grpcVersion"]}")
    implementation("io.grpc", "grpc-netty", "${rootProject.ext["grpcVersion"]}")
    implementation("javax.annotation", "javax.annotation-api", versions["annotations"])
    implementation("org.bitbucket.b_c", "jose4j", versions["jose4j"])
    implementation("com.google.code.gson", "gson", "${rootProject.ext["gson"]}")
}

val generatedProtoBaseDir = "$projectDir/generated"

protobuf {
    generatedFilesBaseDir = generatedProtoBaseDir
    plugins {
        id("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:${rootProject.ext["grpcVersion"]}"
        }
    }
    generateProtoTasks {
        for (p in all()) {
            p.plugins {
                id("grpc")
            }
        }
    }
}

tasks.named("clean") {
    doLast {
        delete(generatedProtoBaseDir)
    }
}

// Include generated grpc files in the ide model
configure<IdeaModel> {
    module {
        generatedSourceDirs.addAll(
            sequenceOf("grpc", "java")
                .map { File("$generatedProtoBaseDir/main/${it}") }
        )
    }
}