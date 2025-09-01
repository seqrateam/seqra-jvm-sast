package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MetaVarConstraint
import org.seqra.semgrep.pattern.MetaVarConstraintFormula
import org.seqra.semgrep.pattern.MetaVarConstraints
import org.seqra.semgrep.pattern.MetavarName
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.ResolvedMetaVarInfo
import org.seqra.semgrep.pattern.TypeName

fun rewriteTypeNameWithMetaVar(
    rule: NormalizedSemgrepRule,
    metaVarInfo: ResolvedMetaVarInfo
): Pair<List<NormalizedSemgrepRule>, ResolvedMetaVarInfo> {
    val generatedMetaVars = hashMapOf<TypeName, String>()

    val rewriter = object : PatternRewriter {
        override fun TypeName.rewriteTypeName(): TypeName {
            if (dotSeparatedParts.size < 2) return this
            if (dotSeparatedParts.all { it !is MetavarName }) return this

            val metaVar = generatedMetaVars.getOrPut(this) {
                "__TYPE#${generatedMetaVars.size}__"
            }

            return TypeName(listOf(MetavarName(metaVar)), typeArgs)
        }
    }

    val modifierRule = rewriter.safeRewrite(rule) { error("No failures expected") }

    if (generatedMetaVars.isEmpty()) {
        return listOf(rule) to metaVarInfo
    }

    val constraints = metaVarInfo.metaVarConstraints.toMutableMap()
    for ((typeName, generatedMetaVar) in generatedMetaVars) {
        val constraintParts = mutableListOf<String>()
        for ((i, name) in typeName.dotSeparatedParts.withIndex()) {
            when (name) {
                is ConcreteName -> constraintParts.add(name.name)
                is MetavarName -> {
                    val currentConstraints = constraints[name.metavarName]
                    if (currentConstraints == null) {
                        constraintParts.add(".*")
                        continue
                    }

                    val constraintFormula = currentConstraints.constraint
                    if (constraintFormula !is MetaVarConstraintFormula.Constraint) {
                        TODO("TypeName metavar with multiple constraints")
                    }

                    val constraint = constraintFormula.constraint
                    when (constraint) {
                        is MetaVarConstraint.Concrete -> constraintParts.add(constraint.value)
                        is MetaVarConstraint.RegExp -> {
                            val normalizedRegex = when (i) {
                                0 -> constraint.regex.trimEnd('$')
                                typeName.dotSeparatedParts.lastIndex -> constraint.regex.trimStart('^')
                                else -> constraint.regex.trimEnd('$').trimStart('^')
                            }
                            constraintParts.add(normalizedRegex)
                        }
                    }
                }
            }
        }

        val pattern = constraintParts.joinToString("\\.")
        constraints[generatedMetaVar] = MetaVarConstraints(
            MetaVarConstraintFormula.Constraint(MetaVarConstraint.RegExp(pattern))
        )
    }

    return modifierRule to ResolvedMetaVarInfo(metaVarInfo.focusMetaVars, constraints)
}
