import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc
import org.gradle.plugins.ide.idea.model.IdeaModel

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val generatedProtoBaseDir = "$projectDir/generated"

protobuf {
    if (findProperty("protocDownload")?.toString()?.toBoolean() != false) {
        this.protoc { artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}" }
    }
    generatedFilesBaseDir = generatedProtoBaseDir
}

tasks.named("clean") {
    doLast {
        delete(generatedProtoBaseDir)
    }
}

configure<IdeaModel> {
    module {
        // mark as generated sources for IDEA
        generatedSourceDirs.add(File("$generatedProtoBaseDir/main/java"))
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

    testImplementation(libs.bundles.testing)
}
