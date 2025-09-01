import org.gradle.api.Project
import org.seqra.common.SeqraDependency

object SeqraProjectDependency : SeqraDependency {
    override val seqraRepository: String = "seqra-project-model"
    override val versionProperty: String = "seqraProjectVersion"

    val Project.seqraProject: String
        get() = propertyDep(group = "org.seqra.project", name = "seqra-project-model")
}
