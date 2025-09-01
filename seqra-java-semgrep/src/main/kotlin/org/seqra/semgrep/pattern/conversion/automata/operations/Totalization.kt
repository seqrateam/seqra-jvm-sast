package org.seqra.semgrep.pattern.conversion.automata.operations

import org.seqra.semgrep.pattern.ResolvedMetaVarInfo
import org.seqra.semgrep.pattern.conversion.automata.AutomataBuilderCtx
import org.seqra.semgrep.pattern.conversion.automata.AutomataEdgeType
import org.seqra.semgrep.pattern.conversion.automata.AutomataNode
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula
import org.seqra.semgrep.pattern.conversion.automata.SemgrepRuleAutomata
import org.seqra.semgrep.pattern.conversion.taint.methodFormulaSat

fun AutomataBuilderCtx.totalizeMethodCalls(
    automata: SemgrepRuleAutomata,
) {
    totalize(automata) { node ->
        methodCallEdgeToDeadNode(automata, node)
    }
}

fun AutomataBuilderCtx.methodCallEdgeToDeadNode(
    automata: SemgrepRuleAutomata,
    node: AutomataNode
): AutomataEdgeType? {
    cancelation.check()

    if (node.outEdges.any { it.first is AutomataEdgeType.MethodCall && it.second == automata.deadNode }) {
        // Edge to dead node already exists
        return null
    }

    val negationFormula = getNodeNegation<AutomataEdgeType.MethodCall>(node)
        ?: return null

    return AutomataEdgeType.MethodCall(negationFormula)
}

fun AutomataBuilderCtx.totalizeMethodEnters(
    metaVarInfo: ResolvedMetaVarInfo,
    automata: SemgrepRuleAutomata,
) {
    automata.hasMethodEnter = true
    totalize(automata) { node ->
       methodEnterEdgeToDeadNode(automata, node)
    }
}

fun AutomataBuilderCtx.methodEnterEdgeToDeadNode(
    automata: SemgrepRuleAutomata,
    node: AutomataNode
): AutomataEdgeType? {
    if (node != automata.initialNode) {
        check(node.outEdges.none { it.first is AutomataEdgeType.MethodEnter }) {
            "Unexpected MethodEnter edge in non-root node"
        }
        return null
    }

    if (node.outEdges.any { it.first is AutomataEdgeType.MethodEnter && it.second == automata.deadNode }) {
        // Edge to dead node already exists
        return null
    }

    val negationFormula = getNodeNegation<AutomataEdgeType.MethodEnter>(node)
        ?: return null

    return AutomataEdgeType.MethodEnter(negationFormula)
}

private fun totalize(
    automata: SemgrepRuleAutomata,
    edgeToDeadNode: (AutomataNode) -> AutomataEdgeType?,
) {
    check(automata.isDeterministic) {
        "Cannot totalize NFA"
    }

    traverse(automata) { node ->
        if (node == automata.deadNode) {
            return@traverse
        }

        val newEdge = edgeToDeadNode(node)
            ?: return@traverse

        node.outEdges.add(newEdge to automata.deadNode)
    }
}

private inline fun <reified EdgeType : AutomataEdgeType.AutomataEdgeTypeWithFormula> AutomataBuilderCtx.getNodeNegation(
    node: AutomataNode,
): MethodFormula? {
    val formulas = node.outEdges.mapNotNull { (it.first as? EdgeType)?.formula?.complement() }

    val result = formulaManager.mkAnd(formulas)
    if (!methodFormulaSat(formulaManager, result, metaVarInfo, cancelation)) {
        return null
    }

    return result
}
