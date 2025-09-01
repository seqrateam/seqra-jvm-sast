package org.seqra.semgrep.pattern.conversion.automata

import org.seqra.semgrep.pattern.conversion.automata.MethodFormula.And
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula.False
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula.Or
import org.seqra.semgrep.pattern.conversion.automata.MethodFormula.True

class MethodFormulaManager {
    private val predicateIds = hashMapOf<Predicate, Int>()
    private val predicates = arrayListOf<Predicate>()

    fun predicateId(predicate: Predicate): PredicateId = predicateIds.getOrPut(predicate) {
        val id = predicates.size
        predicates.add(predicate)
        id + 1
    }

    fun predicate(predicateId: PredicateId): Predicate {
        return predicates[predicateId - 1]
    }

    fun mkCube(cube: MethodFormulaCubeCompact): MethodFormula {
        if (cube.isEmpty) return True
        return MethodFormula.Cube(cube, negated = false)
    }

    fun mkAnd(all: List<MethodFormula>): MethodFormula = when (all.size) {
        0 -> True
        1 -> all.single()
        else -> And(all.toTypedArray())
    }

    fun mkOr(any: List<MethodFormula>): MethodFormula = when (any.size) {
        0 -> False
        1 -> any.single()
        else -> Or(any.toTypedArray())
    }
}
