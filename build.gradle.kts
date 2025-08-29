import SeqraConfigurationDependency.seqraRulesJvm
import SeqraIrDependency.seqra_ir_api_jvm
import SeqraIrDependency.seqra_ir_api_storage
import SeqraIrDependency.seqra_ir_approximations
import SeqraIrDependency.seqra_ir_core
import SeqraIrDependency.seqra_ir_storage
import SeqraProjectDependency.seqraProject
import SeqraUtilDependency.seqraUtilCli
import SeqraUtilDependency.seqraUtilJvm
import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.seqra.common.JunitDependencies
import org.seqra.common.KotlinDependency

plugins {
    id("kotlin-conventions")
    kotlinSerialization()
    shadowPlugin().apply(false)
}

dependencies {
    implementation(seqraUtilJvm)
    implementation(seqraUtilCli)
    implementation(seqraProject)
    implementation(seqraRulesJvm)

    implementation("org.seqra.seqra-dataflow-core:seqra-jvm-dataflow")
    implementation("org.seqra.sast.se:api")

    implementation("org.seqra.sast:project")
    implementation("org.seqra.sast:dataflow")
    implementation(project(":seqra-java-semgrep"))

    implementation(seqra_ir_api_jvm)
    implementation(seqra_ir_core)
    implementation(seqra_ir_approximations)
    implementation(seqra_ir_api_storage)
    implementation(seqra_ir_storage)

    implementation(KotlinDependency.Libs.kotlinx_serialization_json)
    implementation(KotlinDependency.Libs.kotlin_logging)
    implementation(KotlinDependency.Libs.kaml)

    implementation(Libs.sarif4k)
    implementation(Libs.clikt)
    implementation(Libs.zt_exec)

    testImplementation(Libs.mockk)
    testImplementation(JunitDependencies.Libs.junit_jupiter_params)
    implementation(Libs.logback)
    implementation(Libs.jdot)
}

val projectAnalyzerJar = tasks.register<ShadowJar>("projectAnalyzerJar") {
    jarWithDependencies("seqra-project-analyzer", "org.seqra.jvm.sast.runner.ProjectAnalyzerRunner")
}

val encryptedConfig = tasks.register<JavaExec>("encryptedConfig") {
    mainClass.set("org.seqra.jvm.sast.util.ConfigUtils")
    classpath = sourceSets.test.get().runtimeClasspath

    val configFile = layout.projectDirectory.file("config/config.yaml")

    doLast {
        check(configFile.asFile.exists()) { "Configuration file not found" }
    }

    inputs.file(configFile.asFile)

    val result = layout.buildDirectory.file("cfg.enc").get().asFile
    args(configFile.asFile.absolutePath, result.absolutePath)

    outputs.file(result)
}

tasks.register<JavaExec>("runProjectAnalyzer") {
    configureAnalyzer(
        analyzerRunnerClassName = "org.seqra.jvm.sast.runner.ProjectAnalyzerRunner"
    )
}

fun JavaExec.configureAnalyzer(analyzerRunnerClassName: String) {
    dependsOn(encryptedConfig)

    mainClass.set(analyzerRunnerClassName)
    classpath = sourceSets.main.get().runtimeClasspath

    ensureSeEnvInitialized()

    doFirst {
        val envVars = analyzerEnvironment()
        envVars.forEach { (key, value) ->
            environment(key, value)
        }
    }

    systemProperty("org.seqra.ir.impl.storage.defaultBatchSize", 2000)
    systemProperty("jdk.util.jar.enableMultiRelease", false)
    jvmArgs = listOf("-Xmx8g")
}

tasks.register("buildProjectAnalyzerDocker") {
    dependsOn(projectAnalyzerJar)
    analyzerDockerImage(nameSuffix = "private") {
        projectAnalyzerJar.get().outputs.files.singleFile
    }
}

fun Task.analyzerDockerImage(
    nameSuffix: String,
    analyzerJarProvider: () -> File,
) = dependsOn(encryptedConfig)
    .apply { ensureSeEnvInitialized() }
    .doLast {
        val analyzerJar = analyzerJarProvider()

        val contentFiles = mutableListOf(analyzerJar)
        val epVars = mapOf("ANALYZER_JAR_NAME" to analyzerJar.name)

        val rawEnvVars = analyzerEnvironment()
        val envVars = rawEnvVars.mapValues { (_, value) ->
            when (value) {
                is String -> value

                is File -> {
                    contentFiles.add(value)
                    value.name
                }

                else -> error("Unexpected env value: $value")
            }
        }

        buildDockerImage(
            imageName = "analyzer",
            nameSuffix = nameSuffix,
            imageContentFiles = contentFiles,
            entryPointVars = epVars,
            entryPointEnv = envVars,
        )
    }

fun JavaExec.addEnvIfExists(envName: String, path: String) {
    val file = File(path)
    if (!file.exists()) {
        println("Not found $envName at $path")
        return
    }

    environment(envName, file.absolutePath)
}

fun ShadowJar.jarWithDependencies(name: String, mainClass: String) {
    duplicatesStrategy = DuplicatesStrategy.WARN
    archiveBaseName.set(name)

    manifest {
        attributes(mapOf("Main-Class" to mainClass))
    }

    configurations = listOf(project.configurations.runtimeClasspath.get())
    mergeServiceFiles()

    with(tasks.jar.get() as CopySpec)
}

fun analyzerEnvironment(): Map<String, Any> {
    val analyzerEnv = mutableMapOf<String, Any>()

    val configFile = encryptedConfig.get().outputs.files.singleFile
    analyzerEnv["seqra_taint_config_path"] = configFile

    val analyzerVersion = project.findProperty("analyzerVersion") ?: "latest"
    analyzerEnv["SARIF_ORGANIZATION"] = "Seqra"
    analyzerEnv["SARIF_VERSION"] = "$analyzerVersion"

    setupSeqraSeEnvironment(analyzerEnv)

    return analyzerEnv
}

@Suppress("UNCHECKED_CAST")
fun setupSeqraSeEnvironment(analyzerEnv: MutableMap<String, Any>) {
    val initializer = findSeqraSeEnvInitializer() ?: return
    val seEnv = initializer.extra.get("seqra.se.analyzer.env") as Map<String, Any>
    analyzerEnv += seEnv
}

fun Task.ensureSeEnvInitialized() {
    val initializer = findSeqraSeEnvInitializer() ?: return
    dependsOn(initializer)
}

fun findSeqraSeEnvInitializer(): Task? {
    val seProject = gradle.includedBuilds.find { it.name == "seqra-jvm-sast-se" } ?: return null
    return seProject.resolveIncludedProjectTask(":setupAnalyzerEnvironment")
}
