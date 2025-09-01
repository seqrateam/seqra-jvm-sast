package org.seqra.semgrep.pattern.conversion

import org.seqra.semgrep.pattern.EllipsisMethodInvocations
import org.seqra.semgrep.pattern.NormalizedSemgrepRule
import org.seqra.semgrep.pattern.SemgrepJavaPattern

fun rewriteEllipsisMethodInvocations(rule: NormalizedSemgrepRule): List<NormalizedSemgrepRule> {
    val rewriter = object : PatternRewriter {
        override fun createEllipsisMethodInvocations(obj: SemgrepJavaPattern): List<SemgrepJavaPattern> {
            return listOf(
                obj, // Skip it
                EllipsisMethodInvocations(obj), // Don't skip it, will be replaced with single call
            )
        }
    }

    return rewriter.safeRewrite(rule) {
        error("No failures expected")
    }
}
