apply(plugin = "java")

val api by configurations
val testImplementation by configurations

dependencies {
    implementation(project(":idscp2-ra-tpm2d"))
    implementation(rootProject.libs.idscp2.core)
    implementation(rootProject.libs.idscp2.daps)
    implementation(libs.slf4j.simple)
}

task("tpmExampleServer", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.tpm2d.example.RunIdscp2Server")
    classpath = sourceSets["main"].runtimeClasspath
}

task("tpmExampleClient", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.tpm2d.example.RunIdscp2Client")
    classpath = sourceSets["main"].runtimeClasspath
}
