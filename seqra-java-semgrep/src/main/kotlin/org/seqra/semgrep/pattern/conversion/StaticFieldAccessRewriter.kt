package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.conversion.PatternRewriter
import org.seqra.semgrep.pattern.conversion.safeRewrite
import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.FieldAccess
import org.seqra.semgrep.pattern.Name
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.SemgrepJavaPattern
import org.seqra.semgrep.pattern.StaticFieldAccess
import org.seqra.semgrep.pattern.TypeName

fun rewriteStaticFieldAccess(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun FieldAccess.rewriteFieldAccess(): List<SemgrepJavaPattern> {
            val objPattern = when (obj) {
                is FieldAccess.ObjectPattern -> obj.pattern
                FieldAccess.SuperObject -> return listOf(this)
            }

            val objPatternParts = tryExtractPatternDotSeparatedParts(objPattern)
                ?: return listOf(this)

            if (!probablyStaticField(fieldName, objPatternParts)) {
                return listOf(this)
            }

            return listOf(StaticFieldAccess(fieldName, TypeName(objPatternParts)))
        }

        private fun probablyStaticField(fieldName: Name, obj: List<Name>): Boolean {
            if (fieldName is ConcreteName) {
                val name = fieldName.name
                if (name.all { !it.isLetter() || it.isUpperCase() }) return true
            }

            val classNameCandidate = obj.lastOrNull()
            if (classNameCandidate is ConcreteName) {
                val name = classNameCandidate.name
                if (name.firstOrNull()?.isUpperCase() == true) return true
            }

            return false
        }
    }

    return rewriter.safeRewrite(rule) { error("No failures expected") }
}
