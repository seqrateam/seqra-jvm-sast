package org.seqra.semgrep.pattern.conversion.automata.operations

import org.seqra.semgrep.pattern.conversion.automata.AutomataBuilderCtx
import org.seqra.semgrep.pattern.conversion.automata.AutomataEdgeType
import org.seqra.semgrep.pattern.conversion.automata.AutomataNode
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula
import org.seqra.semgrep.pattern.conversion.automata.SemgrepRuleAutomata
import org.seqra.semgrep.pattern.conversion.taint.methodFormulaSat

fun AutomataBuilderCtx.intersection(
    a1: SemgrepRuleAutomata,
    a2: SemgrepRuleAutomata
): SemgrepRuleAutomata {
    check(a1.formulaManager === a2.formulaManager)

    val root = createNewNode(a1.initialNode, a2.initialNode)

    val newNodes = mutableMapOf<Pair<AutomataNode, AutomataNode>, AutomataNode>()
    newNodes[a1.initialNode to a2.initialNode] = root

    val queue = mutableListOf(a1.initialNode to a2.initialNode)

    while (queue.isNotEmpty()) {
        val (n1, n2) = queue.removeFirst()
        val node = newNodes.getOrPut(n1 to n2) {
            createNewNode(n1, n2)
        }

        n1.outEdges.forEach { (outType1, to1) ->
            n2.outEdges.forEach inner@{ (outType2, to2) ->
                val to = newNodes.getOrPut(to1 to to2) {
                    queue.add(to1 to to2)
                    createNewNode(to1, to2)
                }

                val edgeType = if (outType1 == outType2 && outType1 !is AutomataEdgeType.AutomataEdgeTypeWithFormula) {
                    outType1
                } else if (outType1 is AutomataEdgeType.MethodCall && outType2 is AutomataEdgeType.MethodCall) {
                    val formula = intersectMethodFormula(outType1.formula, outType2.formula)
                        ?: return@inner

                    AutomataEdgeType.MethodCall(formula)

                } else if (outType1 is AutomataEdgeType.MethodEnter && outType2 is AutomataEdgeType.MethodEnter) {
                    val formula = intersectMethodFormula(outType1.formula, outType2.formula)
                        ?: return@inner

                    AutomataEdgeType.MethodEnter(formula)

                } else {
                    return@inner
                }

                node.outEdges.add(edgeType to to)
            }
        }
    }

    val intersection = SemgrepRuleAutomata(
        a1.formulaManager,
        setOf(root),
        isDeterministic = a1.isDeterministic && a2.isDeterministic,
        hasMethodEnter = a1.hasMethodEnter && a2.hasMethodEnter,
        hasEndEdges = a1.hasEndEdges && a2.hasEndEdges,
    )

    val unified = unifyMetavars(intersection)
    return unified.also {
        removeDeadNodes(it)
    }
}

private fun createNewNode(n1: AutomataNode, n2: AutomataNode): AutomataNode =
    AutomataNode().also {
        it.accept = n1.accept && n2.accept
    }

private fun AutomataBuilderCtx.intersectMethodFormula(
    f1: MethodFormula,
    f2: MethodFormula
): MethodFormula? {
    val result = formulaManager.mkAnd(listOf(f1, f2))
    if (!methodFormulaSat(formulaManager, result, metaVarInfo, cancelation)) {
        return null
    }

    return result
}
