import SeqraConfigurationDependency.seqraRulesJvm
import SeqraUtilDependency.seqraUtilJvm
import org.seqra.common.KotlinDependency
import SeqraIrDependency.seqra_ir_core
import SeqraIrDependency.seqra_ir_approximations
import SeqraIrDependency.seqra_ir_api_storage
import SeqraIrDependency.seqra_ir_storage

plugins {
    id("kotlin-conventions")
    kotlinSerialization()
    antlr
}

dependencies {
    implementation("org.seqra.seqra-dataflow-core:seqra-dataflow")
    implementation("org.seqra.seqra-dataflow-core:seqra-jvm-dataflow")
    implementation(seqraRulesJvm)
    implementation(seqraUtilJvm)

    implementation(KotlinDependency.Libs.kaml)

    implementation(seqra_ir_core)
    implementation(seqra_ir_approximations)
    implementation(seqra_ir_api_storage)
    implementation(seqra_ir_storage)

    implementation(KotlinDependency.Libs.kotlin_logging)

    implementation(Libs.brics_automaton)
    implementation(Libs.jdot)
    antlr(Libs.antlr)
    implementation(Libs.antlr_runtime)

    testRuntimeOnly(Libs.logback)

    testCompileOnly(project("samples"))
    testImplementation("org.seqra.sast:dataflow")
}

val testSamples by configurations.creating

dependencies {
    testSamples(project("samples"))
}

tasks.withType<Test> {
    dependsOn(project("samples").tasks.withType<Jar>())

    val testSamplesJar = testSamples.resolve().single()
    environment("TEST_SAMPLES_JAR", testSamplesJar.absolutePath)

    val configFile = rootProject.layout.projectDirectory.file("config/config.yaml")
    if (configFile.asFile.exists()) {
        environment("TAINT_CONFIGURATION", configFile.asFile.absolutePath)
    }

    jvmArgs = listOf("-Xmx4g")
}

tasks.generateGrammarSource {
    val pkg = "org.seqra.semgrep.pattern.antlr"
    arguments = arguments + listOf("-package", pkg, "-visitor")
    outputDirectory = outputDirectory.resolve(pkg.split(".").joinToString("/")) // TODO: fix
}

tasks.withType<JavaCompile> {
    options.compilerArgs.remove("-Werror")
}

tasks.compileKotlin {
    dependsOn(tasks.generateGrammarSource)
}

tasks.compileTestKotlin {
    dependsOn(tasks.generateTestGrammarSource)
}