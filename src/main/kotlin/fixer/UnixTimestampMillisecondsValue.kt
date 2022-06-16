package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced
import kotlin.math.absoluteValue

open class UnixTimestampMillisecondsValue(override val entry: LogEntry): Fixer(entry) {

    override val regex: String = "NOT-A-REGEX-FIXER"
    override val reason: String = "Unix timestamp"
    private var storedOffsets: MutableMap<String, Long> = mutableMapOf()

    override fun createReplacement(parameter: ParameterAdvanced): List<String> {
        val offset = storedOffsets[parameter.uniqueIdentifier()]
        val valueFirstOccurrence = if(offset == null) {
            "<@set_variable${entry.hackvertorVariable}('false')><@timestamp/><@/set_variable${entry.hackvertorVariable}>"
        }else if(offset > 0.toLong()) {
            "<@set_variable${entry.hackvertorVariable}('false')><@arithmetic($offset,'+',',')><@timestamp/><@/arithmetic><@/set_variable${entry.hackvertorVariable}>"
        }else{
            "<@set_variable${entry.hackvertorVariable}('false')><@arithmetic(${offset.absoluteValue},'-',',')><@timestamp/><@/arithmetic><@/set_variable${entry.hackvertorVariable}>"
        }
        val valueLaterOccurrence = "<@get_variable${entry.hackvertorVariable} />"
        entry.hackvertorVariable += 1
        return listOf(valueFirstOccurrence, valueLaterOccurrence)
    }

    override fun isEnabled(): Boolean {
        return BurpExtender.ui.settings.replaceUnixTimestamp
    }

    override fun matchesFullMatch(parameter: ParameterAdvanced): String?{
        val offset = getThreeMonthOffset(parameter)
        if(offset != null){
            val identifier = parameter.uniqueIdentifier()
            //Only set offset the first time this is done
            if(!storedOffsets.containsKey(identifier))
                storedOffsets[identifier] = offset
            return parameter.value
        }
        return null
    }

    private fun getThreeMonthOffset(parameter: ParameterAdvanced): Long?{
        try{
            val timestamp = parameter.value.toLong()
            val now = now()
            val aroundThreeMonths: Long = aroundThreeMonths()
            if(timestamp < now + aroundThreeMonths && now < timestamp){
                //Future between now and in three month
                return (timestamp - now)
            }else if(now - aroundThreeMonths < timestamp && timestamp < now){
                //Past between three months ago and now
                return timestamp - now
            }
            return null
        }catch(e: NumberFormatException){
            return null
        }
    }

    open fun now(): Long{
        return System.currentTimeMillis()
    }

    open fun aroundThreeMonths(): Long{
        return 3.toLong() * 30 * 24 * 60 * 60 * 1000.toLong()
    }

}