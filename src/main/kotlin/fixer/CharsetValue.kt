package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class CharsetValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "..+"
    override val reason: String = "rand. Charset"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val lengthValue = parameter.value.length
        val valueFirstOccurrence = "<@set_variable${entry.hackvertorVariable}('false')><@random($lengthValue)>${parameter.value}<@/random><@/set_variable${entry.hackvertorVariable}>"
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceCharset
    }

    override fun matchesFullMatch(parameter: ParameterAdvanced): String?{
        //Everything matches that is longer than 1 character
        //Simply because there is no point in replacing "A" with "A",
        //but "AB" could at least be replaced with "BA" or "AA" or "BB"
        if(parameter.value.length > 1)
            return parameter.value
        return null
    }

}