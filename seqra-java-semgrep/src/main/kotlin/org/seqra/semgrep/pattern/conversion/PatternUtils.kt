package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.FieldAccess
import org.seqra.semgrep.pattern.Identifier
import org.seqra.semgrep.pattern.Metavar
import org.seqra.semgrep.pattern.MetavarName
import org.seqra.semgrep.pattern.Name
import org.seqra.semgrep.pattern.SemgrepJavaPattern

fun tryExtractPatternDotSeparatedParts(pattern: SemgrepJavaPattern): List<Name>? {
    // note: don't match single metavar as dot separated
    if (pattern is Metavar) return null
    return tryExtractPatternDotSeparatedPartsWithMetaVars(pattern)
}

private fun tryExtractPatternDotSeparatedPartsWithMetaVars(pattern: SemgrepJavaPattern): List<Name>? =
    when (pattern) {
        is Identifier -> listOf(ConcreteName(pattern.name))
        is Metavar -> listOf(MetavarName(pattern.name))
        is FieldAccess -> when (val objPattern = pattern.obj) {
            is FieldAccess.ObjectPattern ->
                tryExtractPatternDotSeparatedPartsWithMetaVars(objPattern.pattern)
                    ?.let { it + pattern.fieldName }

            FieldAccess.SuperObject -> null
        }

        else -> null
    }

fun tryExtractConcreteNames(names: List<Name>): List<String>? {
    val result = mutableListOf<String>()
    names.forEach { name ->
        when (name) {
            is ConcreteName -> result.add(name.name)
            is MetavarName -> return null
        }
    }
    return result
}

fun patternFromDotSeparatedParts(dotSeparatedParts: List<String>): SemgrepJavaPattern {
    check(dotSeparatedParts.isNotEmpty())

    if (dotSeparatedParts.size == 1) {
        return Identifier(dotSeparatedParts.single())
    }

    val firstIdentifier = Identifier(dotSeparatedParts.first())
    val names = dotSeparatedParts.drop(1).map { ConcreteName(it) }
    return names.fold(firstIdentifier as SemgrepJavaPattern) { result, name ->
        FieldAccess(name, FieldAccess.ObjectPattern(result))
    }
}
