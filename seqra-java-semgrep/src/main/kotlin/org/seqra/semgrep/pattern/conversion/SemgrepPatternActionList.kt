package org.seqra.semgrep.pattern.conversion

data class SemgrepPatternActionList(
    val actions: List<SemgrepPatternAction>,
    val hasEllipsisInTheEnd: Boolean,
    val hasEllipsisInTheBeginning: Boolean,
)
