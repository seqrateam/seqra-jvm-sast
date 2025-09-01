import org.gradle.api.Task
import org.gradle.api.file.RegularFile
import java.io.File


fun Task.buildDockerImage(
    imageName: String,
    nameSuffix: String,
    imageContentFiles: List<File>,
    entryPointEnv: Map<String, String>,
    entryPointVars: Map<String, String>,
) {
    val analyzerVersion = project.findProperty("analyzerVersion") ?: "latest"
    val dockerTemplatesDir = project.layout.projectDirectory.dir("docker")
    val dockerFileTemplate = dockerTemplatesDir.file("$imageName.template.Dockerfile")
    val entryPointTemplate = dockerTemplatesDir.file("$imageName.template.entrypoint.sh")

    val dockerBuildBaseDir = project.layout.buildDirectory.dir("$imageName-image").get()
    val dockerImageContent = dockerBuildBaseDir.dir("docker-content")
    dockerImageContent.asFile.mkdirs()

    val resolvedEntryPoint = dockerImageContent.file("$imageName.entrypoint.sh")

    val entryPointTemplateVars = entryPointVars.toMutableMap()
    entryPointTemplateVars["ENTRY_POINT_ENV"] = entryPointEnv.entries.joinToString(" ") { (key, value) ->
        "\"$key=$value\""
    }
    resolveTemplate(entryPointTemplate, resolvedEntryPoint, entryPointTemplateVars)

    project.copy {
        imageContentFiles.forEach { file ->
            if (file.isDirectory) {
                from(file) { into(file.name) }
            } else {
                from(file)
            }
        }

        into(dockerImageContent)
    }

    val resolvedDockerFile = dockerBuildBaseDir.file("$imageName.Dockerfile")
    resolveTemplate(
        dockerFileTemplate, resolvedDockerFile, mapOf(
            "DOCKER_IMAGE_CONTENT_PATH" to dockerImageContent.asFile.relativeTo(dockerBuildBaseDir.asFile).path,
            "DOCKER_ENTRYPOINT_SCRIPT" to resolvedEntryPoint.asFile.name,
        )
    )

    project.exec {
        workingDir = dockerBuildBaseDir.asFile
        commandLine(
            "docker", "build",
            "-f", resolvedDockerFile.asFile.name,
            "-t", "$imageName-$nameSuffix:$analyzerVersion",
            "."
        )
    }
}


fun resolveTemplate(template: RegularFile, resolved: RegularFile, variables: Map<String, String>) {
    val templateText = template.asFile.readText()
    val resolvedText = variables.entries.fold(templateText) { result, (varName, value) ->
        result.replace("\$$varName", value)
    }
    resolved.asFile.writeText(resolvedText)
}
