package org.seqra.jvm.sast.dataflow

import org.seqra.ir.api.common.CommonMethod
import org.seqra.ir.api.common.cfg.CommonInst
import org.seqra.ir.api.jvm.JIRField
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRuleFilter
import org.seqra.dataflow.jvm.ap.ifds.taint.TaintRulesProvider

class JIRFilteredTaintRulesProvider(
    private val provider: TaintRulesProvider,
    private val filter: TaintRuleFilter
) : TaintRulesProvider {
    override fun entryPointRulesForMethod(method: CommonMethod) =
        provider.entryPointRulesForMethod(method)
            .filter { filter.ruleEnabled(it) }

    override fun sourceRulesForMethod(method: CommonMethod, statement: CommonInst) =
        provider.sourceRulesForMethod(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethod(method: CommonMethod, statement: CommonInst) =
        provider.sinkRulesForMethod(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun passTroughRulesForMethod(method: CommonMethod, statement: CommonInst) =
        provider.passTroughRulesForMethod(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun cleanerRulesForMethod(method: CommonMethod, statement: CommonInst) =
        provider.cleanerRulesForMethod(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethodExit(method: CommonMethod, statement: CommonInst) =
        provider.sinkRulesForMethodExit(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForAnalysisEnd(method: CommonMethod, statement: CommonInst) =
        provider.sinkRulesForAnalysisEnd(method, statement)
            .filter { filter.ruleEnabled(it) }

    override fun sinkRulesForMethodEntry(method: CommonMethod) =
        provider.sinkRulesForMethodEntry(method)
            .filter { filter.ruleEnabled(it) }

    override fun sourceRulesForStaticField(field: JIRField, statement: CommonInst) =
        provider.sourceRulesForStaticField(field, statement)
            .filter { filter.ruleEnabled(it) }
}
