import SeqraConfigurationDependency.seqraRulesJvm
import SeqraUtilDependency.seqraUtilJvm
import org.seqra.common.KotlinDependency
import SeqraIrDependency.seqra_ir_api_jvm
import SeqraIrDependency.seqra_ir_api_storage
import SeqraIrDependency.seqra_ir_core
import SeqraIrDependency.seqra_ir_storage
import SeqraIrDependency.seqra_ir_approximations

plugins {
    id("kotlin-conventions")
}

dependencies {
    implementation("org.seqra.seqra-dataflow-core:seqra-jvm-dataflow")
    implementation(seqraRulesJvm)
    implementation(seqraUtilJvm)

    implementation(seqra_ir_api_jvm)
    implementation(seqra_ir_core)
    implementation(seqra_ir_approximations)
    implementation(seqra_ir_api_storage)
    implementation(seqra_ir_storage)

    implementation(KotlinDependency.Libs.kotlin_logging)
}
