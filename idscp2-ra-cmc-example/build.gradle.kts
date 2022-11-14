import java.nio.file.Files
import java.nio.file.Paths


apply(plugin = "java")

val api by configurations
val testImplementation by configurations

dependencies {
    implementation(project(":idscp2-ra-tpm2d"))
    implementation(project(":idscp2-ra-cmc"))
    implementation(libs.slf4j.simple)
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

task("cmcExampleServer", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.cmc.example.RunIdscp2Server")
    classpath = sourceSets["main"].runtimeClasspath
}

task("cmcExampleClient", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.cmc.example.RunIdscp2Client")
    classpath = sourceSets["main"].runtimeClasspath
}
