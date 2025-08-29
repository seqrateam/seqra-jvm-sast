import org.seqra.common.KotlinDependency
import SeqraIrDependency.seqra_ir_api_jvm

plugins {
    id("kotlin-conventions")
}

dependencies {
    implementation(seqra_ir_api_jvm)
    implementation(KotlinDependency.Libs.kotlin_logging)
}
