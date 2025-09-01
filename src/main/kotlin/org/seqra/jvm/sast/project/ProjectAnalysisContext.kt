package org.seqra.jvm.sast.project

import kotlinx.coroutines.runBlocking
import mu.KLogging
import org.seqra.ir.api.jvm.JIRClasspath
import org.seqra.ir.api.jvm.JIRDatabase
import org.seqra.ir.approximation.Approximations
import org.seqra.ir.impl.JIRRamErsSettings
import org.seqra.ir.impl.features.InMemoryHierarchy
import org.seqra.ir.impl.features.Usages
import org.seqra.ir.impl.features.classpaths.UnknownClasses
import org.seqra.ir.impl.seqraIrDb
import org.seqra.dataflow.ap.ifds.access.ApMode
import org.seqra.dataflow.jvm.ap.ifds.JIRSummariesFeature
import org.seqra.dataflow.jvm.ap.ifds.LambdaAnonymousClassFeature
import org.seqra.dataflow.jvm.ap.ifds.LambdaExpressionToAnonymousClassTransformerFeature
import org.seqra.dataflow.jvm.graph.MethodReturnInstNormalizerFeature
import org.seqra.jvm.transformer.JMultiDimArrayAllocationTransformer
import org.seqra.jvm.transformer.JStringConcatTransformer
import org.seqra.jvm.util.classpathWithApproximations
import org.seqra.jvm.util.types.installClassScorer
import org.seqra.project.Project
import org.seqra.project.ProjectModuleClasses
import java.io.File

private val logger = object : KLogging() {}.logger

fun initializeProjectAnalysisContext(
    project: Project,
    projectPackage: String?,
    projectKind: ProjectKind,
    summariesApMode: ApMode? = null,
): ProjectAnalysisContext {
    val dependencyFiles by lazy { project.dependencies.map { it.toFile() } }
    val projectModulesFiles by lazy {
        val moduleFiles = mutableMapOf<File, ProjectModuleClasses>()
        for (module in project.modules) {
            for (cls in module.moduleClasses) {
                if (moduleFiles.putIfAbsent(cls.toFile(), module) != null) {
                    logger.warn("Project class $cls belongs to multiple modules")
                }
            }
        }
        moduleFiles
    }

    var db: JIRDatabase
    var cp: JIRClasspath
    var projectClasses: ProjectClasses
    val classPathExtensionFeature = ProjectClassPathExtensionFeature()

    runBlocking {
        val allCpFiles = mutableListOf<File>()
        allCpFiles.addAll(projectModulesFiles.keys)
        allCpFiles.addAll(dependencyFiles)

        db = seqraIrDb {
            val toolchain = project.javaToolchain
            if (toolchain != null) {
                useJavaRuntime(toolchain.toFile())
            } else {
                useProcessJavaRuntime()
            }

            persistenceImpl(JIRRamErsSettings)

            installFeatures(InMemoryHierarchy())
            installFeatures(Usages)
            keepLocalVariableNames()

            installFeatures(Approximations(emptyList()))

            installClassScorer()
            if (summariesApMode != null) {
                installFeatures(JIRSummariesFeature(summariesApMode))
            }

            loadByteCode(allCpFiles)
        }

        db.awaitBackgroundJobs()

        val lambdaAnonymousClass = LambdaAnonymousClassFeature()
        val lambdaTransformer = LambdaExpressionToAnonymousClassTransformerFeature(lambdaAnonymousClass)
        val methodNormalizer = MethodReturnInstNormalizerFeature

        val features = mutableListOf(
            UnknownClasses, lambdaAnonymousClass, lambdaTransformer, methodNormalizer,
            JStringConcatTransformer, JMultiDimArrayAllocationTransformer,
            classPathExtensionFeature
        )

        if (projectKind == ProjectKind.SPRING_WEB) {
            features.add(SpringReactorOperatorsTransformer)
            features.add(SpringAutowiredFieldInitializerTransformer())
        }

        cp = db.classpathWithApproximations(allCpFiles, features)
            ?: run {
                logger.warn {
                    "Classpath with approximations is requested, but some jar paths are missing"
                }
                db.classpath(allCpFiles, features)
            }
//        cp = db.classpath(allCpFiles, features)

        projectClasses = ProjectClasses(cp, projectPackage, projectModulesFiles)
        projectClasses.loadProjectClasses()

        if (projectKind == ProjectKind.SPRING_WEB) {
            cp.features?.filterIsInstance<SpringAutowiredFieldInitializerTransformer>()?.forEach {
                it.init(projectClasses)
            }
        }

        val missedModules = project.modules.toSet() - projectClasses.locationProjectModules.values.toSet()
        if (missedModules.isNotEmpty()) {
            logger.warn {
                "Modules missed for project  ${project.sourceRoot}: ${missedModules.map { it.moduleSourceRoot }}"
            }
        }
    }

    return ProjectAnalysisContext(
        project, projectPackage, projectKind,
        db, cp, projectClasses
    )
}

class ProjectAnalysisContext(
    val project: Project,
    val projectPackage: String?,
    val projectKind: ProjectKind,
    val db: JIRDatabase,
    val cp: JIRClasspath,
    val projectClasses: ProjectClasses,
): AutoCloseable {
    override fun close() {
        cp.close()
        db.close()
    }
}
