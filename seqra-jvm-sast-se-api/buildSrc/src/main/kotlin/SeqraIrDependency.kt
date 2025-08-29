import org.gradle.api.Project
import org.seqra.common.SeqraDependency

object SeqraIrDependency : SeqraDependency {
    override val seqraRepository: String = "seqra-ir"
    override val versionProperty: String = "seqraIrVersion"

    val Project.seqra_ir_core
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-core"
        )

    val Project.seqra_ir_api_common
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-api-common"
        )

    val Project.seqra_ir_api_jvm
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-api-jvm"
        )

    val Project.seqra_ir_api_storage
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-api-storage"
        )

    val Project.seqra_ir_storage
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-storage"
        )

    val Project.seqra_ir_approximations
        get() = propertyDep(
            group = "org.seqra.ir",
            name = "seqra-ir-approximations"
        )
}
