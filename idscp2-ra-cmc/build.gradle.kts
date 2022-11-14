import com.google.protobuf.gradle.generateProtoTasks
import com.google.protobuf.gradle.id
import com.google.protobuf.gradle.plugins
import com.google.protobuf.gradle.protobuf
import com.google.protobuf.gradle.protoc

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val api by configurations
val testImplementation by configurations

dependencies {
    implementation(libs.gson)
    implementation(libs.kotlinx.coroutines)
    implementation(libs.bundles.protobuf)
    implementation(libs.bundles.grpc)
}


// Clears library JARs before copying
val cleanLibs = tasks.create<Delete>("deleteLibs") {
    delete("$buildDir/libs/libraryJars", "$buildDir/libs/projectJars")
}
// Copies all runtime library JARs to build/libs/lib
val rootProjectDir: String = rootProject.projectDir.absolutePath
val copyLibraryJars = tasks.create<Copy>("copyLibraryJars") {
    from(
        configurations.runtimeClasspath.get()
    )
    destinationDir = file("$buildDir/libs/libraryJars")
    dependsOn(cleanLibs)
}
val copyProjectJars = tasks.create<Copy>("copyProjectJars") {
    from(
        configurations.runtimeClasspath.get()
    )
    destinationDir = file("$buildDir/libs/projectJars")
    dependsOn(cleanLibs)
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
