package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced
import java.util.*

class BirthdateValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "\\d\\d\\d\\d-\\d\\d-\\d\\d"
    override val reason: String = "rand. Birthdate"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val startYear = Calendar.getInstance().get(Calendar.YEAR) - 122
        val valueFirstOccurrence = "<@set_variable${entry.hackvertorVariable}('false')><@arithmetic($startYear,'+',',')><@random_num(2)/><@/arithmetic>-0<@random_num(1)/>-0<@random_num(1)/><@/set_variable${entry.hackvertorVariable}>"
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceBirthdate
    }
}