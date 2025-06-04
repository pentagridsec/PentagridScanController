package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class BooleanValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "(true|True|TRUE|false|False|FALSE|0|1)"
    override val reason: String = "other boolean"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val value = when (parameter.value) {
            "true" -> "false"
            "false" -> "true"
            "True" -> "False"
            "False" -> "True"
            "TRUE" -> "FALSE"
            "FALSE" -> "TRUE"
            "1" -> "0"
            "0" -> "1"
            else -> parameter.value
        }
        val newValue = "<@set_variable${entry.hackvertorVariable}('false')>$value</@set_variable${entry.hackvertorVariable}>"
        entry.hackvertorVariable += 1
        return listOf(newValue)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceBoolean
    }

    override fun potentialAddNewMatch(parameter: ParameterAdvanced, match: String){
        changesFullMatch[match] = createReplacement(parameter)
    }

    override fun checkChangesToApply(parameter: ParameterAdvanced, match: String, changesToApply: MutableMap<String, List<String>>): Boolean{
        return changesToApply.containsKey(match)
    }

    override fun newValue(parameter: ParameterAdvanced, match: String, changesToApply: MutableMap<String, List<String>>): String{
        return if(changesToApply[match]!!.size >= 2){
            val newValue = changesToApply[match]!![0]
            changesToApply[match] = changesToApply[match]!!.toMutableList().drop(1)
            newValue
        }else{
            changesToApply[match]!![0]
        }
    }
}