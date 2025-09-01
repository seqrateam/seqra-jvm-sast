package org.seqra.jvm.sast.util

import org.seqra.dataflow.configuration.jvm.serialized.SerializedTaintConfig
import org.seqra.dataflow.configuration.jvm.serialized.loadSerializedTaintConfig
import java.nio.file.Path
import kotlin.io.path.Path

private fun getPathFromEnv(envVar: String): Path =
    System.getenv(envVar)?.let { Path(it) } ?: error("$envVar not provided")

fun loadDefaultConfig(): SerializedTaintConfig =
    ConfigUtils.loadEncrypted(getPathFromEnv("seqra_taint_config_path")) {
        loadSerializedTaintConfig(this)
    }
