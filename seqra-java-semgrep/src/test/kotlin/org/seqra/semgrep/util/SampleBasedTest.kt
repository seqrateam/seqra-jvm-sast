package org.seqra.semgrep.util

import base.RuleSample
import org.seqra.dataflow.configuration.jvm.serialized.SinkMetaData
import org.seqra.semgrep.pattern.SemgrepRuleErrors
import org.seqra.semgrep.pattern.conversion.SemgrepRuleAutomataBuilder
import org.seqra.semgrep.pattern.conversion.taint.convertToTaintRules
import org.seqra.semgrep.pattern.createTaintConfig
import org.seqra.semgrep.pattern.parseSemgrepYaml
import kotlin.io.path.Path
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

abstract class SampleBasedTest(
    private val configurationRequired: Boolean = false
) {
    inline fun <reified T : RuleSample> runTest() =
        runClassTest(getFullyQualifiedClassName<T>())

    fun runClassTest(sampleClassName: String) {
        val data = sampleData[sampleClassName] ?: error("No sample data for $sampleClassName")

        val ruleYaml = parseSemgrepYaml(data.rule)
        val rule = ruleYaml.rules.singleOrNull() ?: error("Not a single rule for ${data.rulePath}")
        check(rule.languages.contains("java"))

        val semgrepRuleErrors = SemgrepRuleErrors(rule.id, rule.id,)
        val builder = SemgrepRuleAutomataBuilder()
        val ruleAutomata = builder.build(rule, semgrepRuleErrors)
        assertFalse(builder.stats.isFailure, "Could not convert rule to Automata: ${builder.stats}")
//        ruleAutomata.forEach { it.view() }

        val rules = convertToTaintRules(ruleAutomata, rule.id, SinkMetaData(), semgrepRuleErrors)
        val taintConfig = rules.createTaintConfig()

        val allSamples = hashSetOf<String>()
        data.positiveClasses.mapTo(allSamples) { it.className }
        data.negativeClasses.mapTo(allSamples) { it.className }

        val configPath = if (configurationRequired) {
            System.getenv("TAINT_CONFIGURATION")
                ?.let { Path(it) }
                ?: error("Configuration file required")
        } else {
            null
        }

        val results = runner.run(taintConfig, configPath, allSamples)

        for (sample in data.positiveClasses) {
            val vulnerabilities = results[sample.className]
            assertNotNull(vulnerabilities, "No results for ${sample.className}")

            assertTrue(
                vulnerabilities.isNotEmpty(),
                "Expected $sample to be positive, but no vulnerability was found."
            )
        }

        for (sample in data.negativeClasses) {
            val vulnerabilities = results[sample.className]
            assertNotNull(vulnerabilities, "No results for ${sample.className}")

            if (vulnerabilities.isEmpty()) continue

            if (sample.ignoreWithMessage != null) {
                System.err.println("Skip ${sample.className}: ${sample.ignoreWithMessage}")
                continue
            }

            assertTrue(
                false,
                "Expected $sample to be negative, but vulnerabilities were found: $vulnerabilities"
            )
        }
    }

    private val samplesDb by lazy { samplesDb() }

    private val sampleData by lazy { samplesDb.loadSampleData() }

    private val runner by lazy { TestAnalysisRunner(samplesDb) }

    fun closeRunner() {
        runner.close()
        samplesDb.close()
    }

    inline fun <reified T> getFullyQualifiedClassName(): String = try {
        T::class.qualifiedName
    } catch (e: NoClassDefFoundError) {
        e.message?.replace('/', '.')
    } ?: error("No class name")
}
