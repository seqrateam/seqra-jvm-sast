import org.gradle.api.Project
import org.seqra.common.SeqraDependency

object SeqraConfigurationDependency : SeqraDependency {
    override val seqraRepository: String = "seqra-configuration-rules"
    override val versionProperty: String = "seqraConfigVersion"

    val Project.seqraRulesJvm: String
        get() = propertyDep(group = "org.seqra.configuration", name = "configuration-rules-jvm")
}
