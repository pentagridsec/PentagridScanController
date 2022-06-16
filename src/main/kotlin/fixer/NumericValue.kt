package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class NumericValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "[0-9]+"
    override val reason: String = "rand. Numeric"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val lengthValue = parameter.value.length
        val valueFirstOccurrence = if(lengthValue > 1)
            "<@set_variable${entry.hackvertorVariable}('false')><@arithmetic(${parameter.value},'+',',')><@random_num(${lengthValue - 1})/><@/arithmetic><@/set_variable${entry.hackvertorVariable}>"
        else
            "<@set_variable${entry.hackvertorVariable}('false')><@random_num(2)/><@/set_variable${entry.hackvertorVariable}>"
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceNumeric
    }
}