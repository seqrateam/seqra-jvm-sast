package org.seqra.semgrep.pattern.conversion.automata.operations

import org.seqra.semgrep.pattern.conversion.automata.SemgrepRuleAutomata

fun complement(automata: SemgrepRuleAutomata) {
    check(automata.isDeterministic) {
        "Cannot get complement of NFA"
    }
    traverse(automata) {
        it.accept = !it.accept
    }
    automata.deadNode = SemgrepRuleAutomata.createDeadNode()
}
