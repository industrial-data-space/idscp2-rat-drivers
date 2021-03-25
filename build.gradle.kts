import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    id("com.google.protobuf") version "0.8.15"
    id("org.jetbrains.kotlin.jvm") version "1.4.31"
    id("com.diffplug.spotless") version "5.11.0"
    id("com.github.jk1.dependency-license-report") version "1.16"
}

allprojects {
    group = "de.fhg.aisec.ids"

    repositories {
        mavenCentral()
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
        // Logging API
        api("org.slf4j", "slf4j-simple", "1.7.30")
        api("de.fhg.aisec.ids", "idscp2", "0.4.0")
        api("org.jetbrains.kotlin", "kotlin-stdlib-jdk8", "1.4.31")
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

    apply(plugin = "com.github.jk1.dependency-license-report")

    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("**/*.kt")
            ktlint("0.41.0")
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
