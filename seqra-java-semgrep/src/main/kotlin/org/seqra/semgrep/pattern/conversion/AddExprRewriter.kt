package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.ConcreteName
import org.seqra.semgrep.pattern.MethodInvocation
import org.seqra.semgrep.pattern.NoArgs
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.PatternArgumentPrefix
import org.seqra.semgrep.pattern.SemgrepJavaPattern

// todo: rewrite all AddExpr as string concat for now
// we can consider split on string/non-string
// or seqra.plus utility method with special handling in engine
fun rewriteAddExpr(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createAddExpr(left: SemgrepJavaPattern, right: SemgrepJavaPattern): List<SemgrepJavaPattern> =
            listOf(generateStringConcat(left, right))
    }

    return rewriter.safeRewrite(rule) {
        error("No failures expected")
    }
}

const val generatedStringConcatMethodName = "__genStringConcat__"

private fun generateStringConcat(first: SemgrepJavaPattern, second: SemgrepJavaPattern): SemgrepJavaPattern {
    val args = PatternArgumentPrefix(first, PatternArgumentPrefix(second, NoArgs))
    return MethodInvocation(ConcreteName(generatedStringConcatMethodName), obj = null, args)
}
