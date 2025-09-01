package org.seqra.semgrep.pattern.conversion.automata

class AutomataNode {
    val outEdges = mutableListOf<Pair<AutomataEdgeType, AutomataNode>>()
    var accept = false

    private fun deepCopy(newNodes: MutableMap<AutomataNode, AutomataNode>): AutomataNode {
        check(this !in newNodes)
        val newNode = AutomataNode().also { it.accept = accept }
        newNodes[this] = newNode
        outEdges.forEach { (type, to) ->
            val toNode = newNodes.getOrPut(to) {
                to.deepCopy(newNodes)
            }
            newNode.outEdges.add(type to toNode)
        }
        return newNode
    }

    fun deepCopy(): Pair<AutomataNode, Map<AutomataNode, AutomataNode>> {
        val newNodes = mutableMapOf<AutomataNode, AutomataNode>()
        return deepCopy(newNodes) to newNodes
    }
}
