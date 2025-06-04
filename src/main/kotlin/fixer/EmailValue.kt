package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced

class EmailValue(override val entry: LogEntry): Fixer(entry) {

    //Email address has to start with [a-zA-Z] so we can make sure we match &param=foo@example.org correctly
    override val regex: String = "(?:[a-zA-Z][a-zA-Z0-9!#\$%&'*+/=?^_`{|}~-]*(?:\\.[a-zA-Z0-9!#\$%&'*+/=?^_`{|}~-]+)*|\"(?:[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x21\\x23-\\x5b\\x5d-\\x7f]|\\\\[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f])*\")"
    override val reason: String = "rand. Email"

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val valueFirstOccurrence: String = if(BurpExtender.ui.settings.catchAllEmail.isNotEmpty() &&
            parameter.value.matches(Regex(fullMatchRegexDomain(BurpExtender.ui.settings.catchAllEmail)))){
            "<@set_variable${entry.hackvertorVariable}('false')><@random_num(12)/></@set_variable${entry.hackvertorVariable}>@${BurpExtender.ui.settings.catchAllEmail}"
        }else{
            val colab = BurpExtender.c.createBurpCollaboratorClientContext()?.collaboratorServerLocation
            if(colab != null && parameter.value.matches(Regex(fullMatchRegexDomain(colab))))
                "<@set_variable${entry.hackvertorVariable}('false')><@random_num(12)/></@set_variable${entry.hackvertorVariable}>@$colab"
            else
                "<@set_variable${entry.hackvertorVariable}('false')><@random_num(12)/></@set_variable${entry.hackvertorVariable}>@$colab"
        }
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceEmail
    }

    override fun matchesFullMatch(parameter: ParameterAdvanced): String?{
        if(BurpExtender.ui.settings.catchAllEmail.isNotEmpty()) {
            if (parameter.value.matches(Regex(fullMatchRegexDomain(BurpExtender.ui.settings.catchAllEmail))))
                return parameter.value
        }
        val colab = BurpExtender.c.createBurpCollaboratorClientContext()?.collaboratorServerLocation
        if(colab != null) {
            if (parameter.value.matches(Regex(fullMatchRegexDomain(colab))))
                return parameter.value
        }
        return null
    }

    private fun fullMatchRegexDomain(domain: String): String {
        return "^$regex@$domain$"
    }

}