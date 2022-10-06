import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    signing
    `maven-publish`
    alias(libs.plugins.protobuf)
    alias(libs.plugins.kotlin)
    alias(libs.plugins.spotless)
    alias(libs.plugins.license.report)
    alias(libs.plugins.versions)
}

val descriptions: Map<String, String> = mapOf(
    "idscp2-ra-tpm2d" to "IDSCP2 TPM 2.0 Remote Attestation Driver",
    "idscp2-ra-cmc" to "IDSCP2 CMC Remote Attestation Driver",
    "idscp2-ra-snp" to "IDSCP2 SEV-SNP Remote Attestation Driver",
)

allprojects {
    group = "de.fhg.aisec.ids"
    version = rootProject.libs.versions.idscp2.get()

    repositories {
        mavenCentral()
    }

    tasks.withType<com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask> {
        rejectVersionIf {
            ".*(rc-?[0-9]*|beta)$".toRegex(RegexOption.IGNORE_CASE).matches(candidate.version)
        }
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "kotlin")

    java {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        withSourcesJar()
        withJavadocJar()
    }

    tasks.test {
        exclude("**/*IT.*")
    }

    val integrationTest = tasks.register<Test>("integrationTest") {
        include("**/*IT.*")
        systemProperty("project.version", "$project.version")
    }

    tasks.withType<Test> {
        testLogging {
            events("failed")
            exceptionFormat = TestExceptionFormat.FULL
        }
    }

    tasks.check {
        dependsOn(integrationTest)
    }

    dependencies {
        implementation(rootProject.libs.slf4j.api)
        implementation(rootProject.libs.idscp2)
        implementation(rootProject.libs.kotlin.stdlib)
        testImplementation(rootProject.libs.slf4j.simple)
    }

    tasks.withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = "11"
        }
    }

    tasks.withType<JavaCompile> {
        options.encoding = "UTF-8"
        // options.compilerArgs.add("-Xlint:unchecked")
        // options.isDeprecation = true
    }

    tasks.jar {
        manifest {
            attributes(
                "Bundle-Vendor" to "Fraunhofer AISEC",
                "-noee" to true
            )
        }
    }

    if (project.name in descriptions.keys) {
        apply(plugin = "maven-publish")
        apply(plugin = "signing")

        publishing {
            publications {
                register("idscp2Library", MavenPublication::class) {
                    from(components["java"])
                    pom {
                        name.set(project.name)
                        description.set(descriptions[project.name])
                        url.set("https://github.com/industrial-data-space/idscp2-rat-drivers")
                        licenses {
                            license {
                                name.set("The Apache License, Version 2.0")
                                url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                            }
                        }
                        developers {
                            developer {
                                name.set("Michael Lux")
                                email.set("michael.lux@aisec.fraunhofer.de")
                                organization.set("Fraunhofer AISEC")
                                organizationUrl.set("aisec.fraunhofer.de")
                            }
                        }
                        scm {
                            connection.set("scm:git:git://github.com:industrial-data-space/idscp2-rat-drivers.git")
                            developerConnection.set("scm:git:ssh://github.com:industrial-data-space/idscp2-rat-drivers.git")
                            url.set("https://github.com/industrial-data-space/idscp2-rat-drivers")
                        }
                    }
                }
            }

            repositories {
                // mavenLocal()
                maven {
                    url = uri(
                        if (version.toString().endsWith("SNAPSHOT")) {
                            "https://oss.sonatype.org/content/repositories/snapshots"
                        } else {
                            "https://oss.sonatype.org/service/local/staging/deploy/maven2"
                        }
                    )

                    credentials {
                        username = project.findProperty("deployUsername") as? String
                        password = project.findProperty("deployPassword") as? String
                    }
                }
            }
        }

        signing {
            useGpgCmd()
            sign(publishing.publications.getByName("idscp2Library"))
        }
    }

    apply(plugin = "com.github.jk1.dependency-license-report")

    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("**/*.kt")
            ktlint(libs.versions.ktlint.get())
            licenseHeader(
                """/*-
 * ========================LICENSE_START=================================
 * ${project.name}
 * %%
 * Copyright (C) ${"$"}YEAR Fraunhofer AISEC
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * =========================LICENSE_END==================================
 */"""
            ).yearSeparator(" - ")
        }
    }
}
