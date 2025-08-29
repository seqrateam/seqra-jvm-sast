import kotlin.io.path.Path
import kotlin.io.path.div
import kotlin.io.path.exists

rootProject.name = "seqra-jvm-sast"

include("seqra-java-semgrep")
include("seqra-java-semgrep:samples")

fun DependencySubstitutions.substituteProjects(group: String, projects: List<String>) {
    for (projectName in projects) {
        substitute(module("$group:$projectName")).using(project(":$projectName"))
    }
}

includeBuild("seqra-dataflow-core") {
    dependencySubstitution {
        substituteProjects("org.seqra.seqra-dataflow-core", listOf("seqra-dataflow", "seqra-jvm-dataflow"))
    }
}

includeBuild("seqra-jvm-sast-dataflow") {
    dependencySubstitution {
        substitute(module("org.seqra.sast:dataflow")).using(project(":"))
    }
}

includeBuild("seqra-jvm-sast-project") {
    dependencySubstitution {
        substitute(module("org.seqra.sast:project")).using(project(":"))
    }
}

includeBuild("seqra-jvm-sast-se-api") {
    dependencySubstitution {
        substitute(module("org.seqra.sast.se:api")).using(project(":"))
    }
}

if (Path("seqra-jvm-sast-se").div("settings.gradle.kts").exists()) {
    includeBuild("seqra-jvm-sast-se")
}
