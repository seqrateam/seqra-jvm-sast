package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MethodInvocation
import org.seqra.semgrep.pattern.NoArgs
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.PatternArgumentPrefix
import org.seqra.semgrep.pattern.SemgrepJavaPattern

const val generatedReturnValueMethod = "__genReturnValue__"

fun rewriteReturnStatement(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createReturnStmt(value: SemgrepJavaPattern?): List<SemgrepJavaPattern> {
            val valuePattern = value ?: return super.createReturnStmt(value)
            val args = PatternArgumentPrefix(valuePattern, NoArgs)
            return listOf(MethodInvocation(ConcreteName(generatedReturnValueMethod), obj = null, args))
        }
    }

    return rewriter.safeRewrite(rule) { error("No failures expected") }
}
