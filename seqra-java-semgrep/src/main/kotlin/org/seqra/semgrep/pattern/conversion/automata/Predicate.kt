package org.seqra.semgrep.pattern.conversion.automata

import org.seqra.semgrep.pattern.conversion.ParamCondition
import org.seqra.semgrep.pattern.conversion.SemgrepPatternAction.SignatureModifier
import org.seqra.semgrep.pattern.conversion.SemgrepPatternAction.SignatureName
import org.seqra.semgrep.pattern.conversion.TypeNamePattern

typealias PredicateId = Int

data class Predicate(
    val signature: MethodSignature,
    val constraint: MethodConstraint?,
)

data class MethodSignature(
    val methodName: MethodName,
    val enclosingClassName: MethodEnclosingClassName,
)

sealed interface MethodConstraint

data class ParamConstraint(
    val position: Position,
    val condition: ParamCondition.Atom,
) : MethodConstraint

data class NumberOfArgsConstraint(val num: Int) : MethodConstraint

data class ClassModifierConstraint(val modifier: SignatureModifier) : MethodConstraint

data class MethodModifierConstraint(val modifier: SignatureModifier) : MethodConstraint

data class MethodName(val name: SignatureName)

data class MethodEnclosingClassName(val name: TypeNamePattern) {
    companion object {
        val anyClassName = MethodEnclosingClassName(name = TypeNamePattern.AnyType)
    }
}

sealed interface Position {
    sealed interface ArgumentIndex {
        data class Concrete(val idx: Int) : ArgumentIndex
        data class Any(val paramClassifier: String) : ArgumentIndex
    }

    data class Argument(val index: ArgumentIndex) : Position
    data object Object : Position
    data object Result : Position
}
