package org.seqra.jvm.sast.project

import org.seqra.ir.api.jvm.JIRClassOrInterface
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.ir.api.jvm.JIRClasspathExtFeature
import org.seqra.ir.impl.features.classpaths.AbstractJIRResolvedResult.JIRResolvedClassResultImpl
import java.util.concurrent.ConcurrentHashMap

class ProjectClassPathExtensionFeature : JIRClasspathExtFeature {
    private val classPathExtension = ConcurrentHashMap<String, JIRClassOrInterface>()

    override fun tryFindClass(classpath: JIRClasspath, name: String): JIRClasspathExtFeature.JIRResolvedClassResult? {
        val clazz = classPathExtension[name]
        if (clazz != null) {
            return JIRResolvedClassResultImpl(name, clazz)
        }
        return null
    }

    fun extendClassPath(cls: JIRClassOrInterface) {
        classPathExtension[cls.name] = cls
    }

    fun containsClass(className: String): Boolean =
        classPathExtension.containsKey(className)
}
