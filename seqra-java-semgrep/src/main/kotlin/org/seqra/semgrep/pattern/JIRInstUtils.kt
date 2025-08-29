package org.seqra.semgrep.pattern

import org.seqra.ir.api.jvm.cfg.JIRAssignInst
import org.seqra.ir.api.jvm.cfg.JIRCatchInst
import org.seqra.ir.api.jvm.cfg.JIRInst
import org.seqra.ir.api.jvm.cfg.JIRLocalVar

fun JIRInst.isVariableDeclaration(): JIRLocalVar? {
    return when (this) {
        is JIRAssignInst -> lhv as? JIRLocalVar
        is JIRCatchInst -> throwable as? JIRLocalVar
        else -> null
    }
}