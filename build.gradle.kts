import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    kotlin("jvm") version "1.5.31"
    kotlin("plugin.serialization") version "1.5.31"
}

group = "me.user"
version = "0.1"

//Klaxon needs at least version 11
java.sourceCompatibility = JavaVersion.VERSION_11
java.targetCompatibility = JavaVersion.VERSION_11

repositories {
    mavenCentral()
}


dependencies {
    // https://mvnrepository.com/artifact/net.portswigger.burp.extender/burp-extender-api
    //implementation("net.portswigger.burp.extender:burp-extender-api:2.3")
    implementation(kotlin("stdlib", org.jetbrains.kotlin.config.KotlinCompilerVersion.VERSION))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-runtime:0.20.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.3.2")
    implementation("com.beust:klaxon:5.6")
}

tasks.withType<KotlinCompile> {
    //Klaxon needs at least version 11
    kotlinOptions.jvmTarget = "11"
}

tasks.withType<Jar> {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
        attributes["Main-Class"] = "ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender"
    }
    from(sourceSets.main.get().output)
    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
}
