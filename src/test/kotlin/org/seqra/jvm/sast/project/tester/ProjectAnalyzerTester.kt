package org.seqra.jvm.sast.project.tester

import kotlinx.serialization.json.Json
import mu.KLogging
import org.seqra.dataflow.ap.ifds.access.ApMode
import org.seqra.dataflow.ap.ifds.trace.VulnerabilityWithTrace
import org.seqra.dataflow.configuration.CommonTaintConfigurationSinkMeta
import org.seqra.dataflow.configuration.jvm.AssignMark
import org.seqra.dataflow.configuration.jvm.ConstantTrue
import org.seqra.dataflow.configuration.jvm.ContainsMark
import org.seqra.dataflow.configuration.jvm.TaintCleaner
import org.seqra.dataflow.configuration.jvm.TaintConfigurationItem
import org.seqra.dataflow.configuration.jvm.TaintMark
import org.seqra.dataflow.configuration.jvm.TaintMethodEntrySink
import org.seqra.dataflow.configuration.jvm.TaintMethodExitSink
import org.seqra.dataflow.configuration.jvm.TaintMethodSink
import org.seqra.dataflow.configuration.jvm.TaintMethodSource
import org.seqra.dataflow.configuration.jvm.TaintPassThrough
import org.seqra.dataflow.configuration.jvm.TaintSinkMeta
import org.seqra.dataflow.configuration.jvm.TaintStaticFieldSource
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.ir.api.jvm.cfg.JIRInst
import org.seqra.ir.api.jvm.ext.findMethodOrNull
import org.seqra.jvm.sast.dataflow.DummySerializationContext
import org.seqra.jvm.sast.dataflow.JIRTaintAnalyzer
import org.seqra.jvm.sast.dataflow.JIRTaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration
import org.seqra.jvm.sast.project.ProjectAnalysisContext
import org.seqra.jvm.sast.project.ProjectKind
import org.seqra.jvm.sast.project.initializeProjectAnalysisContext
import org.seqra.jvm.sast.project.selectProjectEntryPoints
import org.seqra.jvm.sast.util.loadDefaultConfig
import org.seqra.project.Project
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.time.Duration

private val logger = object : KLogging() {}.logger

@Suppress("unused")
fun testProjectAnalyzerOnTraces(
    project: Project,
    projectPackage: String?,
    ifdsAnalysisTimeout: Duration,
    ifdsApMode: ApMode,
    projectKind: ProjectKind,
    testDataJsonPath: Path,
    debugOptions: JIRTaintAnalyzer.DebugOptions
) {
    val testDataTaintConfig: List<TracePair> = Json.decodeFromString(
        testDataJsonPath.readText()
    )

    val analysisContext = initializeProjectAnalysisContext(project, projectPackage, projectKind)

    val mainConfig = JIRTaintRulesProvider(
        TaintConfiguration(analysisContext.cp).also { it.loadConfig(loadDefaultConfig()) }
    )

    val visitedAtSourceMarks = hashSetOf<TaintMark>()
    val stats = analysisContext.use {
        val testData = it.loadTestData(testDataTaintConfig)
        val config = createTestConfig(testData, mainConfig, visitedAtSourceMarks)
        val entryPoints = it.selectProjectEntryPoints()

        logger.info { "Start running tests" }
        val traces = it.analyze(config, entryPoints, ifdsAnalysisTimeout, ifdsApMode, debugOptions)
        getStats(traces, testData, visitedAtSourceMarks)
    }
    logger.info { "Total number of marks: ${stats.marksTotal}" }

    logger.info { "Sources not found: ${stats.sourcesNotFound.size} (recall=${String.format("%.2f", stats.sourcesRecall)})" }
    logger.debug { "Marks for missed sources: ${stats.sourcesNotFound}" }

    logger.info { "Sinks not found: ${stats.sinksNotFound.size} (recall=${String.format("%.2f", stats.sinksRecall)})" }
    logger.debug { "Marks for missed sinks: ${stats.sinksNotFound}" }
}

private data class ProjectTestData(
    val testDataByMark: Map<String, TracePair>,
    val testDataBySourceInst: Map<JIRInst, List<TracePair>>,
    val testDataBySinkInst: Map<JIRInst, List<TracePair>>
)

private fun ProjectAnalysisContext.loadTestData(testDataTaintConfig: List<TracePair>): ProjectTestData {
    fun TraceLocation.method(): JIRMethod? =
        cp.findClassOrNull(cls)?.findMethodOrNull(methodName, methodDesc)

    fun TraceLocation.inst(): JIRInst? =
        method()?.instList?.getOrNull(instIndex)
            .takeIf { it.toString() == instStr }
            .also {
                if (it == null) {
                    logger.warn { "Instruction $this not found" }
                }
            }

    val validTestData = testDataTaintConfig.filter {
        it.source.location.inst() != null && it.sink.location.inst() != null
    }

    val testDataByMark = validTestData
        .groupBy { it.source.mark }
        .mapValues { (_, trace) -> trace.single() }

    val testDataBySourceInst = validTestData.groupBy { it.source.location.inst()!! }
    val testDataBySinkInst = validTestData.groupBy { it.sink.location.inst()!! }

    return ProjectTestData(testDataByMark, testDataBySourceInst, testDataBySinkInst)
}

private fun createTestConfig(
    testData: ProjectTestData,
    mainConfig: TaintRulesProvider,
    visitedAtSourceMarks: MutableSet<TaintMark>
): TaintRulesProvider = object : TaintRulesProvider {
    override fun entryPointRulesForMethod(method: CommonMethod) =
        mainConfig.entryPointRulesForMethod(method)

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        testData.testDataBySourceInst[statement].orEmpty().map { trace ->
            val source = trace.source
            val mark = TaintMark(source.mark)
            visitedAtSourceMarks.add(mark)

            TaintMethodSource(
                method = method,
                condition = ConstantTrue,
                actionsAfter = listOf(AssignMark(mark, specializePosition(it, source.position).single()))
            )
        }
    }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        testData.testDataBySinkInst[statement].orEmpty().map { trace ->
            val sink = trace.sink
            val meta = TaintSinkMeta(
                message = "Path generated by symbolic engine",
                severity = CommonTaintConfigurationSinkMeta.Severity.Error,
                cwe = null
            )
            TaintMethodSink(
                method = method,
                condition = ContainsMark(specializePosition(it, sink.position).single(), TaintMark(sink.mark)),
                id = sink.mark,
                meta = meta,
            )
        }
    }

    override fun sinkRulesForMethodExit(
        method: CommonMethod,
        statement: CommonInst
    ) = getRules(method) {
        emptyList<TaintMethodExitSink>()
    }

    override fun sinkRulesForAnalysisEnd(
        method: CommonMethod,
        statement: CommonInst
    ) = getRules(method) {
        emptyList<TaintMethodExitSink>()
    }

    override fun sinkRulesForMethodEntry(method: CommonMethod) = getRules(method) {
        emptyList<TaintMethodEntrySink>()
    }

    override fun passTroughRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        if (it.enclosingClass.declaration.location.isRuntime) {
            return@getRules mainConfig.passTroughRulesForMethod(it, statement)
        }

        emptyList<TaintPassThrough>()
    }

    override fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        emptyList<TaintCleaner>()
    }

    override fun sourceRulesForStaticField(
        field: JIRField,
        statement: CommonInst
    ): Iterable<TaintStaticFieldSource> = emptyList()

    private inline fun <T : TaintConfigurationItem> getRules(
        method: CommonMethod,
        body: (JIRMethod) -> Iterable<T>
    ): Iterable<T> {
        check(method is JIRMethod) { "Expected method to be JIRMethod" }
        return body(method)
    }
}

private fun ProjectAnalysisContext.analyze(
    config: TaintRulesProvider,
    entryPoints: List<JIRMethod>,
    ifdsAnalysisTimeout: Duration,
    ifdsApMode: ApMode,
    debugOptions: JIRTaintAnalyzer.DebugOptions
): List<VulnerabilityWithTrace> {
    JIRTaintAnalyzer(
        cp, config,
        projectLocations = projectClasses.projectLocations,
        ifdsTimeout = ifdsAnalysisTimeout,
        ifdsApMode = ifdsApMode,
        symbolicExecutionEnabled = false,
        analysisCwe = null,
        summarySerializationContext = DummySerializationContext,
        storeSummaries = false,
        debugOptions = debugOptions
    ).use { analyzer ->
        return analyzer.analyzeWithIfds(entryPoints)
    }
}

private fun getStats(
    ifdsTraces: List<VulnerabilityWithTrace>,
    testData: ProjectTestData,
    visitedAtSourceMarks: Set<TaintMark>
): EvaluationStats {
    val visitedAtSinkMarks = ifdsTraces.map {
        val rule = it.vulnerability.rule
        val condition = (rule as TaintMethodSink).condition

        check(condition is ContainsMark) { "Unexpected rule with non-trivial condition: $condition" }
        condition.mark
    }.toSet()

    val allMarks = testData.testDataByMark.keys.mapTo(hashSetOf()) { TaintMark(it) }
    return EvaluationStats(
        marksTotal = allMarks.size,
        sourcesNotFound = allMarks.filterNot { it in visitedAtSourceMarks },
        sinksNotFound = allMarks.filterNot { it in visitedAtSinkMarks }
    )
}

data class EvaluationStats(
    val marksTotal: Int,
    val sourcesNotFound: List<TaintMark>,
    val sinksNotFound: List<TaintMark>
) {
    val sinksRecall: Double
        get() = 1.0 * (marksTotal - sinksNotFound.size) / marksTotal

    val sourcesRecall: Double
        get() = 1.0 * (marksTotal - sourcesNotFound.size) / marksTotal
}
