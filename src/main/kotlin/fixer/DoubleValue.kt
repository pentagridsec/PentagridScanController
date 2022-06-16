package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class DoubleValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "-?[0-9]+[.][0-9]+"
    override val reason: String = "rand. Double"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val lengths = parameter.value.split(".", limit=2).map{it.replace("-","").length}
        if(lengths.size != 2){
            BurpExtender.println("DoubleValue: Something is wrong, ${parameter.value} was split into != 2 parts")
            return listOf(parameter.value, parameter.value)
        }
        val (beforeLength, afterLength) = lengths
        val sign = if("-" in parameter.value) "-" else ""
        val valueFirstOccurrence = "<@set_variable${entry.hackvertorVariable}('false')>$sign<@random_num(${beforeLength})/>.<@random_num(${afterLength})/><@/set_variable${entry.hackvertorVariable}>"
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceDouble
    }
}