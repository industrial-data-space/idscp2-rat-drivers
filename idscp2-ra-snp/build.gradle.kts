import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc
import org.gradle.plugins.ide.idea.model.IdeaModel

apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

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

val generatedProtoBaseDir = "$projectDir/generated"

protobuf {
    generatedFilesBaseDir = generatedProtoBaseDir
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
                .map { File("$generatedProtoBaseDir/main/$it") }
        )
    }
}
