version = "0.2.2"

apply(plugin = "java")

val api by configurations
val testImplementation by configurations

dependencies {
    api(project(":idscp2-rat-tpm2d"))

    api("org.slf4j", "slf4j-simple", "1.7.30")
}

task("TpmExampleServer", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.tpm2d.example.RunIdscp2Server")
    classpath = sourceSets["main"].runtimeClasspath
}

task("TpmExampleClient", JavaExec::class) {
    mainClass.set("de.fhg.aisec.ids.tpm2d.example.RunIdscp2Client")
    classpath = sourceSets["main"].runtimeClasspath
}
