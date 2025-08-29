package org.seqra.jvm.sast.dataflow

import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.ir.api.jvm.JIRMethod
import org.seqra.dataflow.configuration.jvm.TaintConfigurationItem
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider
import org.seqra.jvm.sast.dataflow.rules.TaintConfiguration

class JIRTaintRulesProvider(
    private val taintConfiguration: TaintConfiguration
) : TaintRulesProvider {
    override fun entryPointRulesForMethod(method: CommonMethod) = getRules(method) {
        taintConfiguration.entryPointForMethod(it)
    }

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.sourceForMethod(it)
    }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.sinkForMethod(it)
    }

    override fun passTroughRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.passThroughForMethod(it)
    }

    override fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.cleanerForMethod(it)
    }

    override fun sinkRulesForMethodExit(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.methodExitSinkForMethod(it)
    }

    override fun sinkRulesForAnalysisEnd(method: CommonMethod, statement: CommonInst) = getRules(method) {
        taintConfiguration.analysisEndSinkForMethod(it)
    }

    override fun sinkRulesForMethodEntry(method: CommonMethod) = getRules(method) {
        taintConfiguration.methodEntrySinkForMethod(it)
    }

    override fun sourceRulesForStaticField(field: JIRField, statement: CommonInst) =
        taintConfiguration.sourceForStaticField(field)

    private inline fun <T : TaintConfigurationItem> getRules(
        method: CommonMethod,
        body: (JIRMethod) -> Iterable<T>
    ): Iterable<T> {
        check(method is JIRMethod) { "Expected method to be JIRMethod" }
        return body(method)
    }
}
