package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.Combiner
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.ParameterFilter

abstract class Fixer(open val entry: LogEntry) {

    // Create additional Value subclasses:
    // TODO FEATURE: IsoTimestampValue (2019-10-21T06:05:50.000Z)

    /*
    By default a fixer is based on a regex. However, feel free to reimplement the methods below to use other criteria
     */
    open val regex: String = "NOT-A-REGEX-FIXER"
    abstract val reason: String

    // LinkedHashMap preserves ordering
    val changesFullMatch = LinkedHashMap<String, List<String>>()
    var combinationsFullMatch: List<List<Int>> = mutableListOf()

    fun createReplacements(): Int {
        for(parameter in ParameterFilter.filter(entry.modifiedRequestInfo.parameters)){
            //if(acceptParameter(parameter)) {
                val match = matchesFull(parameter)
                if(match != null){
                    //if(BurpExtender.ui.settings.debug)
                    //    BurpExtender.println("Found parameter name ${parameter.name} with value ${parameter.value} matching ${fullMatchRegex(parameter)}")
                    potentialAddNewMatch(parameter, match)
                }
            //}
        }

        val mods = (0 until changesFullMatch.size).toMutableList()
        combinationsFullMatch = Combiner.allCombinations(mods)

        return changesFullMatch.size
    }

    fun noOfReplacementsEstimation(): Int {
        return if(changesFullMatch.size > 0){
            changesFullMatch.size
        }else{
            createReplacements()
        }
    }

    fun makeModificationsAllFullMatch() {
        makeModificationsFullMatch(changesFullMatch.toMutableMap()) //toMutableMap so it gets copied
    }

    fun makeModificationsComboFullMatch(combo: List<Int>): Int {
        if(combo.isEmpty())
            return 0
        // We can only do this because mutableMap says:
        //"The returned map preserves the entry iteration order."
        //copy the map
        val changesToApply = changesFullMatch.toMutableMap()
        val keys = ArrayList(changesToApply.keys)
        for(i in keys.indices){
            if(!combo.contains(i)){
                changesToApply.remove(keys[i])
            }
        }
        if(BurpExtender.ui.settings.debug)
            BurpExtender.println("makeModificationsComboFullMatch: $changesToApply")
        return makeModificationsFullMatch(changesToApply)
    }

    fun makeModificationsFullMatch(changesToApply: MutableMap<String, List<String>>): Int {
        var numberOfModifications = 0
        for(parameter in ParameterFilter.filter(entry.modifiedRequestInfo.parameters)){
            val match = matchesFull(parameter)
            if(match != null){
                //if(BurpExtender.ui.settings.debug)
                //    BurpExtender.println("Found parameter name ${parameter.name} with value ${parameter.value} matching ${fullMatchRegex(parameter)}")
                if(checkChangesToApply(parameter, match, changesToApply)){
                    val newValue: String = newValue(parameter, match, changesToApply)
                    numberOfModifications += 1
                    if(BurpExtender.ui.settings.debug)
                        BurpExtender.println(
                                    "CLASS: ${this.javaClass.name.split(".").last()}, " +
                                    "PARAM-TYPE: ${String.format("%02X", parameter.type)}, " +
                                    "NAME: ${parameter.name}, " +
                                    "OLD VALUE: ${parameter.value}, " +
                                    "NEW VALUE: $newValue."
                                    //"MATCHING ${fullMatchRegex(parameter)}, " +
                        )
                    val newParam = BurpExtender.h.buildParameter(parameter, value=newValue)
                    val newRequest: ByteArray = BurpExtender.h.updateParameter(entry.modifiedMessageInfo.request, newParam)
                    entry.modifiedMessageInfo.request = newRequest
                }
            }
            else{
                //BurpExtender.println("makeModifications: ${parameter.name}, ${parameter.value} does not match ${regex}")
            }
        }
        return numberOfModifications
    }

    /*
    By default we replace same values with same values. Meaning:
    abc=FooBar&cde=FooBar will be replaced with abc=Example&cde=Example
    This makes sense for most cases and reduces the combinatoric explosion a little.
    However, for Boolean values this does not make sense:
    abc=True&cde=True
    So they should be changed independently. We allow this to the BooleanValue by providing the following three functions:
     */

    open fun potentialAddNewMatch(parameter: ParameterAdvanced, match: String){
        if (!changesFullMatch.containsKey(match)) {
            changesFullMatch[match] = createReplacement(parameter)
        }
    }

    open fun checkChangesToApply(parameter: ParameterAdvanced, match: String, changesToApply: MutableMap<String, List<String>>): Boolean{
        return changesToApply.containsKey(match)
    }

    open fun newValue(parameter: ParameterAdvanced, match: String, changesToApply: MutableMap<String, List<String>>): String{
        return if(changesToApply[match]!!.size >= 2){
            val newValue = changesToApply[match]!![0]
            changesToApply[match] = changesToApply[match]!!.toMutableList().drop(1)
            newValue
        }else{
            changesToApply[match]!![0]
        }
    }

    /*
    By default a fixer is based on a regex. However, feel free to reimplement the methods below here to use other criteria
     */

    fun matchesFull(parameter: ParameterAdvanced): String?{
        //This is important for the rest of our logic, so subclasses can't override this function
        //Not match everything where we already injected our hackvertor tags
        if(parameter.value.contains("<@set_variable") || parameter.value.contains("<@get_variable"))
            return null
        return matchesFullMatch(parameter)
    }

    open fun matchesFullMatch(parameter: ParameterAdvanced): String?{
        if(parameter.value.matches(Regex(fullMatchRegex(parameter))))
            return parameter.value
        return null
    }

    open fun fullMatchRegex(parameter: ParameterAdvanced): String {
        return "^$regex$"
    }

    open fun acceptParameter(parameter: ParameterAdvanced): Boolean {
        //TODO: Maybe there is a specific case in the future where parameter and fix type don't fit?
        //e.g. don't change email values in cookies. But so far I can't think of any. We already ignore cookies globally.
        return true
    }

    abstract fun createReplacement(parameter: ParameterAdvanced): List<String>
    abstract fun isEnabled(): Boolean

}