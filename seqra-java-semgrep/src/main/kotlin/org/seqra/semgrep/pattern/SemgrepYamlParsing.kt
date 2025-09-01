package org.seqra.semgrep.pattern

import com.charleskorn.kaml.Yaml
import com.charleskorn.kaml.YamlConfiguration
import com.charleskorn.kaml.YamlMap
import com.charleskorn.kaml.YamlNode
import com.charleskorn.kaml.YamlScalar
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer
import org.seqra.semgrep.pattern.conversion.cartesianProductMapTo
import org.slf4j.event.Level
import java.util.Optional
import kotlin.jvm.optionals.getOrNull

@Serializable
data class SemgrepYamlRuleSet(
    val rules: List<SemgrepYamlRule>,
)

@Serializable
data class SemgrepYamlRule(
    val id: String,
    val languages: List<String>,
    val pattern: String? = null,
    val mode: String? = null,
    val patterns: List<ComplexPattern> = emptyList(),
    @SerialName("pattern-either")
    val patternEither: List<ComplexPattern> = emptyList(),
    val message: String,
    val severity: String,
    val metadata: YamlMap? = null,
    @SerialName("pattern-sources")
    val patternSources: List<PatternSource> = emptyList(),
    @SerialName("pattern-sinks")
    val patternSinks: List<PatternSink> = emptyList(),
    @SerialName("pattern-propagators")
    val patternPropagators: List<PatternPropagator> = emptyList(),
    @SerialName("pattern-sanitizers")
    val patternSanitizers: List<ComplexPattern> = emptyList(),
)

@Serializable
data class ComplexPattern(
    @SerialName("pattern-either")
    val patternEither: List<ComplexPattern> = emptyList(),
    val pattern: String? = null,
    val patterns: List<ComplexPattern> = emptyList(),
    @SerialName("pattern-inside")
    private val rawPatternInside: YamlNode? = null,
    @SerialName("pattern-not")
    private val rawPatternNot: YamlNode? = null,
    @SerialName("pattern-not-inside")
    private val rawPatternNotInside: YamlNode? = null,
    @SerialName("metavariable-regex")
    val metavariableRegex: MetavariableRegexInfo? = null,
    @SerialName("metavariable-pattern")
    private val rawMetaVariablePattern: YamlNode? = null,
    @SerialName("metavariable-comparison")
    val metavariableComparison: MetavariableComparisonInfo? = null,
    @SerialName("pattern-regex")
    val patternRegex: String? = null,
    @SerialName("pattern-not-regex")
    val patternNotRegex: String? = null,
    @SerialName("focus-metavariable")
    private val rawFocusMetavariable: YamlNode? = null,
) {
    @Transient
    val metaVariablePattern: MetavariablePatternInfo? = rawMetaVariablePattern?.decodeMetavariablePatternInfo()
    @Transient
    val focusMetaVariables: List<String>? = rawFocusMetavariable?.decodeFocusMetaVariables()
    @Transient
    val patternInside: SimpleOrComplexPattern? = rawPatternInside?.decodeSimpleOrComplexPattern()
    @Transient
    val patternNot: SimpleOrComplexPattern? = rawPatternNot?.decodeSimpleOrComplexPattern()
    @Transient
    val patternNotInside: SimpleOrComplexPattern? = rawPatternNotInside?.decodeSimpleOrComplexPattern()
}

sealed interface SimpleOrComplexPattern {
    data class Simple(val pattern: String) : SimpleOrComplexPattern
    data class Complex(val pattern: ComplexPattern) : SimpleOrComplexPattern
}

private fun YamlNode.decodeSimpleOrComplexPattern(): SimpleOrComplexPattern {
    if (this is YamlScalar) {
        return SimpleOrComplexPattern.Simple(content)
    }

    val pattern = yaml.decodeFromYamlNode<ComplexPattern>(this)
    return SimpleOrComplexPattern.Complex(pattern)
}

private fun YamlNode.decodeMetavariablePatternInfo(): MetavariablePatternInfo =
    yaml.decodeFromYamlNode<MetavariablePatternInfo>(this)

private fun YamlNode.decodeFocusMetaVariables(): List<String> {
    if (this is YamlScalar) {
        return listOf(content)
    }

    return yaml.decodeFromYamlNode<List<String>>(this)
}

@Serializable
data class MetavariableRegexInfo(
    val metavariable: String,
    val regex: String,
)

@Serializable
data class MetavariableComparisonInfo(
    val metavariable: String,
    val comparison: String,
)

@Serializable(MetaVariablePatternInfoSerializer::class)
data class MetavariablePatternInfo(
    val metavariable: String,
    val metaVariablePattern: ComplexPattern,
)

@Serializable(PatternPropagatorSerializer::class)
data class PatternPropagator(
    val from: String,
    val to: String,
    val propagatorPattern: ComplexPattern,
)

@Serializable(PatternSourceSerializer::class)
data class PatternSource(
    val label: String? = null,
    val requires: String? = null,
    val sourcePattern: ComplexPattern,
)

@Serializable(PatternSinkSerializer::class)
data class PatternSink(
    val requires: String? = null,
    val sinkPattern: ComplexPattern,
)

private const val metaVariableField = "metavariable"

private object MetaVariablePatternInfoSerializer
    : InlineCompositeObjectSerializer<MetavariablePatternInfo, ComplexPattern>(
    name = "metavariable-pattern-info",
    objSerializer = ComplexPattern.serializer(),
    inlinedFields = listOf(metaVariableField to String.serializer())
) {
    override fun deserialize(obj: ComplexPattern, fields: Map<String, Optional<Any>>): MetavariablePatternInfo {
        val metaVar = fields[metaVariableField]?.map { it as String }?.getOrNull() ?: error("deserialization failed")
        return MetavariablePatternInfo(metaVar, obj)
    }
}

private const val fromField = "from"
private const val toField = "to"

private object PatternPropagatorSerializer
    : InlineCompositeObjectSerializer<PatternPropagator, ComplexPattern>(
    name = "pattern-propagator",
    objSerializer = ComplexPattern.serializer(),
    inlinedFields = listOf(fromField to String.serializer(), toField to String.serializer()),
) {
    override fun deserialize(obj: ComplexPattern, fields: Map<String, Optional<Any>>): PatternPropagator {
        val fromValue = fields[fromField]?.map { it as String }?.getOrNull() ?: error("deserialization failed")
        val toValue = fields[toField]?.map { it as String }?.getOrNull() ?: error("deserialization failed")
        return PatternPropagator(fromValue, toValue, obj)
    }
}

private const val labelField = "label"
private const val requiresField = "requires"

private object PatternSourceSerializer : InlineCompositeObjectSerializer<PatternSource, ComplexPattern>(
    name = "pattern-source",
    objSerializer = ComplexPattern.serializer(),
    inlinedFields = listOf(labelField to String.serializer(), requiresField to String.serializer()),
) {
    override fun deserialize(obj: ComplexPattern, fields: Map<String, Optional<Any>>): PatternSource {
        val label = fields[labelField]?.map { it as String }?.getOrNull()
        val requires = fields[requiresField]?.map { it as String }?.getOrNull()
        return PatternSource(label, requires, obj)
    }
}

private object PatternSinkSerializer : InlineCompositeObjectSerializer<PatternSink, ComplexPattern>(
    name = "pattern-sink",
    objSerializer = ComplexPattern.serializer(),
    inlinedFields = listOf(requiresField to String.serializer()),
) {
    override fun deserialize(obj: ComplexPattern, fields: Map<String, Optional<Any>>): PatternSink {
        val requires = fields[requiresField]?.map { it as String }?.getOrNull()
        return PatternSink(requires, obj)
    }
}

sealed interface Formula {
    data class LeafPattern(val pattern: String) : Formula
    class And(val children: List<Formula>) : Formula
    class Or(val children: List<Formula>) : Formula
    class Not(val child: Formula) : Formula
    class Inside(val child: Formula) : Formula
    data class MetavarRegex(val name: String, val regex: String) : Formula
    data class MetavarFocus(val name: String) : Formula
    data class MetavarPattern(val name: String, val formula: Formula) : Formula
    data class MetavarCond(val name: String) : Formula // TODO
    data class Regex(val pattern: String) : Formula
}

private val yaml = Yaml(
    configuration = YamlConfiguration(
        strictMode = false,
    )
)

fun parseSemgrepYaml(yml: String): SemgrepYamlRuleSet =
    yaml.decodeFromString(SemgrepYamlRuleSet.serializer(), yml)

fun yamlToSemgrepRule(yml: String): List<SemgrepYamlRule> {
    val ruleSet = parseSemgrepYaml(yml)
    return ruleSet.rules.filter { rule ->
        "java" in rule.languages.map { it.lowercase() }
    }
}

fun parseSemgrepRule(rule: SemgrepYamlRule): SemgrepRule<Formula> =
    if (rule.mode == "taint") {
        parseTaintRule(rule)
    } else {
        SemgrepMatchingRule(listOf(parseMatchingRuleFormula(rule)))
    }

private fun parseTaintRule(rule: SemgrepYamlRule): SemgrepTaintRule<Formula> =
    SemgrepTaintRule(
        sources = rule.patternSources.map {
            SemgrepTaintSource(it.label, it.requires, complexPatternToFormula(it.sourcePattern))
        },
        sinks = rule.patternSinks.map {
            SemgrepTaintSink(it.requires, complexPatternToFormula(it.sinkPattern))
        },
        propagators = rule.patternPropagators.map {
            SemgrepTaintPropagator(it.from, it.to, complexPatternToFormula(it.propagatorPattern))
        },
        sanitizers = rule.patternSanitizers.map { complexPatternToFormula(it) }
    )

// TODO The case in which two or more of them are simultaneously contained has not been considered.
private fun parseMatchingRuleFormula(rule: SemgrepYamlRule): Formula =
    if (rule.pattern != null) {
        Formula.LeafPattern(rule.pattern)
    } else if (rule.patterns.isNotEmpty()) {
        val children = rule.patterns.map { complexPatternToFormula(it) }
        Formula.And(children)
    } else if (rule.patternEither.isNotEmpty()) {
        val children = rule.patternEither.map { complexPatternToFormula(it) }
        Formula.Or(children)
    } else {
        TODO()
    }

fun convertToRawRule(rule: SemgrepRule<Formula>,
                     semgrepError : AbstractSemgrepError): SemgrepRule<RuleWithMetaVars<RawSemgrepRule, RawMetaVarInfo>> {
    return rule.flatMap { convertToRawRule(it, semgrepError) }
}

fun convertToRawRule(formula: Formula,
                     semgrepError : AbstractSemgrepError
): List<RuleWithMetaVars<RawSemgrepRule, RawMetaVarInfo>> {
    val formulaDnf = formula.normalizeToNNF(negated = false).toDNF()
    return formulaDnf.mapNotNull { convertToNormalizedRule(it.literals, semgrepError) }
}

private fun convertToNormalizedRule(literals: List<NormalizedFormula.Literal>,
                                    semgrepError : AbstractSemgrepError): RuleWithMetaVars<RawSemgrepRule, RawMetaVarInfo>? {
    val patterns = mutableListOf<String>()
    val patternNots = mutableListOf<String>()
    val patternInsides = mutableListOf<String>()
    val patternNotInsides = mutableListOf<String>()
    val metaVariableConstraints = hashMapOf<String, MutableSet<MetaVarConstraintFormula<RawMetaVarConstraint>>>()
    val focusMetaVars = hashSetOf<String>()

    for (literal in literals) {
        when (val f = literal.formula) {
            is Formula.LeafPattern -> if (literal.negated) {
                patternNots.add(f.pattern)
            } else {
                patterns.add(f.pattern)
            }

            is Formula.Inside -> {
                val inside = f.child
                val insideAsLeaf = inside as? Formula.LeafPattern
                    ?: TODO()
                if (literal.negated) {
                    patternNotInsides.add(insideAsLeaf.pattern)
                } else {
                    patternInsides.add(insideAsLeaf.pattern)
                }
            }

            is Formula.MetavarFocus -> {
                // todo
                if (literal.negated)  {
                    semgrepError += SemgrepError(
                        SemgrepError.Step.BUILD_CONVERT_TO_RAW_RULE,
                        "Not implemented negated MetavarFocus",
                        Level.TRACE,
                        SemgrepError.Reason.NOT_IMPLEMENTED,
                    )
                    return null
                }

                focusMetaVars.add(f.name)
            }

            is Formula.MetavarCond -> {
                semgrepError += SemgrepError(
                    SemgrepError.Step.BUILD_CONVERT_TO_RAW_RULE,
                    "Not implemented MetavarCond",
                    Level.TRACE,
                    SemgrepError.Reason.NOT_IMPLEMENTED
                )
                // todo
                return null
            }

            is Formula.MetavarPattern -> {
                var metaVarConstraint = f.formula.toMetaVarPatternConstraint()
                if (metaVarConstraint == null) {
                    semgrepError += SemgrepError(
                        SemgrepError.Step.BUILD_CONVERT_TO_RAW_RULE,
                        "Not implemented complex MetavarPattern",
                        Level.TRACE,
                        SemgrepError.Reason.NOT_IMPLEMENTED
                    )
                    // todo
                    return null
                }

                if (literal.negated) {
                    metaVarConstraint = MetaVarConstraintFormula.mkNot(metaVarConstraint)
                }

                metaVariableConstraints.getOrPut(f.name, ::hashSetOf).add(metaVarConstraint)
            }

            is Formula.MetavarRegex -> {
                val regexConstraint = RawMetaVarConstraint.RegExp(f.regex)
                var metaVarConstraint: MetaVarConstraintFormula<RawMetaVarConstraint> = MetaVarConstraintFormula.Constraint(regexConstraint)

                if (literal.negated) {
                    metaVarConstraint = MetaVarConstraintFormula.mkNot(metaVarConstraint)
                }

                metaVariableConstraints.getOrPut(f.name, ::hashSetOf).add(metaVarConstraint)
            }

            is Formula.Regex -> {
                semgrepError += SemgrepError(
                    SemgrepError.Step.BUILD_CONVERT_TO_RAW_RULE,
                    "Not implemented Regex",
                    Level.TRACE,
                    SemgrepError.Reason.NOT_IMPLEMENTED
                )
                // todo
                return null
            }

            is Formula.Not,
            is Formula.And,
            is Formula.Or -> error("Unexpected formula in dnf")
        }
    }

    return RuleWithMetaVars(
        RawSemgrepRule(
            patterns, patternNots, patternInsides, patternNotInsides
        ),
        RawMetaVarInfo(
            focusMetaVars,
            metaVariableConstraints.mapValues { (_, constraints) ->
                MetaVarConstraintFormula.mkAnd(constraints)
            },
        )
    )
}

private fun Formula.toMetaVarPatternConstraint(): MetaVarConstraintFormula<RawMetaVarConstraint>? {
    return when (this) {
        is Formula.LeafPattern -> MetaVarConstraintFormula.Constraint(RawMetaVarConstraint.Pattern(pattern))
        is Formula.Regex -> MetaVarConstraintFormula.Constraint(RawMetaVarConstraint.RegExp(pattern))
        is Formula.Not -> child.toMetaVarPatternConstraint()?.let { MetaVarConstraintFormula.mkNot(it) }
        is Formula.And -> children.mapTo(hashSetOf()) { it.toMetaVarPatternConstraint() ?: return null }
            .let { MetaVarConstraintFormula.mkAnd(it) }

        else -> null
    }
}

private sealed interface NormalizedFormula {
    data class Literal(val formula: Formula, val negated: Boolean) : NormalizedFormula
    data class And(val children: List<NormalizedFormula>) : NormalizedFormula
    data class Or(val children: List<NormalizedFormula>) : NormalizedFormula
}

private data class NormalizedFormulaCube(val literals: List<NormalizedFormula.Literal>)

private fun NormalizedFormulaCube.toFormula(): Formula {
    val args = literals.map { if (it.negated) Formula.Not(it.formula) else it.formula }
    return when (args.size) {
        1 -> args.first()
        else -> Formula.And(args)
    }
}

private fun Formula.normalizeToNNF(negated: Boolean): NormalizedFormula = when (this) {
    is Formula.Inside, // todo: handle inside nested formula
    is Formula.LeafPattern,
    is Formula.MetavarCond,
    is Formula.MetavarRegex,
    is Formula.MetavarFocus,
    is Formula.Regex -> NormalizedFormula.Literal(this, negated)

    is Formula.MetavarPattern -> {
        if (!negated) {
            val nestedDnf = formula.normalizeToNNF(negated = false).toDNF()
            val lits = nestedDnf.map {
                val f = Formula.MetavarPattern(name, it.toFormula())
                NormalizedFormula.Literal(f, negated)
            }
            NormalizedFormula.Or(lits)
        } else {
            NormalizedFormula.Literal(this, negated)
        }
    }

    is Formula.Not -> child.normalizeToNNF(!negated)
    is Formula.And -> if (!negated) {
        NormalizedFormula.And(children.map { it.normalizeToNNF(negated = false) })
    } else {
        NormalizedFormula.Or(children.map { it.normalizeToNNF(negated = true) })
    }

    is Formula.Or -> if (!negated) {
        NormalizedFormula.Or(children.map { it.normalizeToNNF(negated = false) })
    } else {
        NormalizedFormula.And(children.map { it.normalizeToNNF(negated = true) })
    }
}

private fun NormalizedFormula.toDNF(): List<NormalizedFormulaCube> = when (this) {
    is NormalizedFormula.Literal -> listOf(NormalizedFormulaCube(listOf(this)))
    is NormalizedFormula.Or -> children.flatMap { it.toDNF() }

    is NormalizedFormula.And -> {
        val dnfChildren = children.map { it.toDNF() }
        val resultCubes = mutableListOf<NormalizedFormulaCube>()
        dnfChildren.cartesianProductMapTo { cubes ->
            val literals = mutableListOf<NormalizedFormula.Literal>()
            cubes.forEach { literals.addAll(it.literals) }
            resultCubes += NormalizedFormulaCube(literals)
        }
        resultCubes
    }
}

private fun complexPatternToFormula(pattern: ComplexPattern): Formula {
    return if (pattern.patternEither.isNotEmpty()) {
        val children = pattern.patternEither.map { complexPatternToFormula(it) }
        Formula.Or(children)
    } else if (pattern.pattern != null) {
        Formula.LeafPattern(pattern.pattern)
    } else if (pattern.patterns.isNotEmpty()) {
        val children = pattern.patterns.map { complexPatternToFormula(it) }
        Formula.And(children)
    } else if (pattern.patternInside != null) {
        Formula.Inside(
            complexPatternToFormula(pattern.patternInside)
        )
    } else if (pattern.patternNot != null) {
        Formula.Not(
            complexPatternToFormula(pattern.patternNot)
        )
    } else if (pattern.patternNotInside != null) {
        Formula.Not(
            Formula.Inside(
                complexPatternToFormula(pattern.patternNotInside)
            )
        )
    } else if (pattern.metaVariablePattern != null) {
        val nested = pattern.metaVariablePattern.metaVariablePattern
        val nestedFormula = complexPatternToFormula(nested)
        Formula.MetavarPattern(pattern.metaVariablePattern.metavariable, nestedFormula)
    } else if (pattern.metavariableRegex != null) {
        Formula.MetavarRegex(pattern.metavariableRegex.metavariable, pattern.metavariableRegex.regex)
    } else if (pattern.metavariableComparison != null) {
        Formula.MetavarCond(pattern.metavariableComparison.metavariable)
    } else if (pattern.patternRegex != null) {
        Formula.Regex(pattern.patternRegex)
    } else if (pattern.patternNotRegex != null) {
        Formula.Not(Formula.Regex(pattern.patternNotRegex))
    } else if (pattern.focusMetaVariables != null) {
        val focusVars = pattern.focusMetaVariables.map { Formula.MetavarFocus(it) }
        return Formula.And(focusVars)
    } else {
        TODO()
    }
}

private fun complexPatternToFormula(pattern: SimpleOrComplexPattern): Formula = when (pattern) {
    is SimpleOrComplexPattern.Simple -> Formula.LeafPattern(pattern.pattern)
    is SimpleOrComplexPattern.Complex -> complexPatternToFormula(pattern.pattern)
}
