import org.gradle.plugin.use.PluginDependenciesSpec
import org.seqra.common.KotlinDependency
import org.seqra.common.id

fun PluginDependenciesSpec.kotlinSerialization() = id(KotlinDependency.Plugins.KotlinSerialization)
