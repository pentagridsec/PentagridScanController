package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class UuidValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    override val reason: String = "rand. UUID"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val valueFirstOccurrence =
            parameter.value.dropLast(12) + "<@set_variable${entry.hackvertorVariable}('false')><@random_num(12)/></@set_variable${entry.hackvertorVariable}>"
        val valueLaterOccurrence =
            parameter.value.dropLast(12) + "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceUuid
    }
}