version = "0.6.0"

apply(plugin = "java")
apply(plugin = "com.google.protobuf")
apply(plugin = "idea")

val api by configurations
val testImplementation by configurations

dependencies {
    api("com.google.code.gson", "gson", "2.8.7")
}
