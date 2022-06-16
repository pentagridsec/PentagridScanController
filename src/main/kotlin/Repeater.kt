package ch.pentagrid.burpexts.pentagridscancontroller

import burpwrappers.SerializableHttpRequestResponse
import kotlin.reflect.KFunction0
import ch.pentagrid.burpexts.pentagridscancontroller.fixer.*
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.Combiner
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.ParameterFilter
import ui.TableModel

class Repeater(val entry: LogEntry) {

    private var sender: RepeaterSender = RepeaterSender(entry)
    private var detector: RepeatableDetector = RepeatableDetector(sender, entry)

    fun achieveRepeatable(): Boolean {
        //detector = RepeatableDetector(sender, entry)
        return if(detector.isLookingRepeatable(false)) {
            entry.repeatabilityFixNumberOfSentRequests = 1
            BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.repeatabilityColumn)
            entry.reasons += "+1:1 repeatable"
            entry.reasons.addAll(detector.reasonsForSuccess)
            BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            true
        } else{
            entry.reasons += "-Not 1:1"
            entry.reasons.addAll(detector.reasonsForFail)
            tryFixingRepeatability()
        }
    }

    private fun tryFixingRepeatability(): Boolean{
        if(BurpExtender.ui.settings.debug)
            BurpExtender.println("# Trying to fix repeatability with parameters " +
                    ParameterFilter.filter(entry.originalRequestInfo.parameters).mapNotNull {
                        it.name }.sortedBy { it }.joinToString(":")
            )
        /*
        It's nearly impossible to understand this logic without an example. So let's try to explain with one.
        The following POST request has the form:
            POST /A/__A__/a.php

            b=A&c=B
        Where uppercase letters indicate the same values. For example A=A and B=B but A!=B. Let's create an example
        with UUIDs:
            POST /AAAAAAAA-2F9E-4886-A838-5BCE9084016A/__AAAAAAAA-2F9E-4886-A838-5BCE9084016A__/a.php

            b=AAAAAAAA-2F9E-4886-A838-5BCE9084016A&c=BBBBBBBB-ff4f-4da6-8eff-9f8114354b4B&d=foo@example.org
        Then:
            - Regex Fixer takes care that all A will always be replaced with the same value. See valueFirstOccurrence
              and valueLaterOccurence logic which uses Hackvertor setVariable and getVariable.
            - applyFull means: We always change A and B to a new value. We don't send a request yet where A is
              changed but B isn't.
            - makeModificationsFullMatch means: the entire parameter value has to match. Meaning A matches,
              but __A__ is not a match.
            -
        Issues:
            - UUIDs have a defined length. But for example with emails it is getting harder: is __ part of the
              email address or not? We counter this by requiring email addresses to start with a letter [a-zA-Z]
            - Burp being too stupid to change JSON values, we do a search/replace in JSON bodies, breaking
              our entire logic (for example of makeModificationsFullMatch) for now.
         */

        val allFails: MutableSet<String> = mutableSetOf()
        val lastMessageInfo: MutableSet<SerializableHttpRequestResponse> = mutableSetOf(entry.modifiedMessageInfo)
        // First, modify each parameter separately, then modify all occurrences at once,
        // then do the combinatoric explosion of all other combinations
        val modificationApproaches: List<KFunction0<Sequence<Modification>>> = listOf(::applyOneFullMatch, ::applyAllFullMatch, ::applyCombinatoricFullMatch)
        for(modificationApproach in modificationApproaches){
            try {
                val success = applyApproach(modificationApproach, allFails, lastMessageInfo)
                if(success)
                    return true
            }catch(e: AbortRepeatabilityTestsException){
                return false
            }
        }

        //However, let's explain to the user why the last request did not succeed at least
        entry.modifiedMessageInfo = lastMessageInfo.first()
        entry.reasons += "-No approach worked (encountered reasons follow)"
        entry.reasons.addAll(allFails)
        BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
        return false
    }

    private fun applyApproach(modificationApproach: KFunction0<Sequence<Modification>>,
                              allFails: MutableSet<String>,
                              lastMessageInfo: MutableSet<SerializableHttpRequestResponse>): Boolean {
        for(modification in modificationApproach().iterator()){
            if(modification.totalNumberModifications > 0 && detector.isLookingRepeatable()){
                entry.repeatabilityFixNumberOfSentRequests = sender.sentRequests.size
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.repeatabilityColumn)
                entry.reasons.addAll(modification.reasons)
                entry.reasons.addAll(detector.reasonsForSuccess)
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                //TODO FEATURE: Mark strategies as favorites and try those ones first on the next request
                //Needs a data structure outside of Repeater, as Repeater is newly created with every request
                //But then we also need to store it globally... so maybe this is a actually a setting?
                //We could even give the user the chance to set it differently...
                //markStrategyAsFavorite(strategy)
                return true
            }
            if(detector.fatal >= BurpExtender.ui.settings.heuristicMaxFatal){
                entry.repeatabilityFixNumberOfSentRequests = sender.sentRequests.size
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.repeatabilityColumn)
                entry.reasons += "-${BurpExtender.ui.settings.heuristicMaxFatal} fatal heuristic keywords"
                entry.reasons.addAll(allFails)
                entry.reasons.addAll(detector.reasonsForFail)
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                throw AbortRepeatabilityTestsException()
            }
            //TODO: We have to defend against infinite loops here if sender.sentRequests is not getting larger
            //The * 10 is a "not that cheap" workaround
            if(sender.sentRequests.size >= BurpExtender.ui.settings.maxRepeatabilityProbesPerRequest ||
                sender.pureCounter >= BurpExtender.ui.settings.maxRepeatabilityProbesPerRequest * 10){
                entry.repeatabilityFixNumberOfSentRequests = sender.sentRequests.size
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.repeatabilityColumn)
                entry.reasons += "-maximum repeatability probes reached (encountered reasons follow)"
                entry.reasons.addAll(allFails)
                entry.reasons.addAll(detector.reasonsForFail)
                if(sender.pureCounter >= BurpExtender.ui.settings.maxRepeatabilityProbesPerRequest * 10) {
                    BurpExtender.println("Warning, assuming we would have gone into an infinite loop, aborting.")
                    entry.reasons += "-No response from server, is the server down?"
                }
                BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                throw AbortRepeatabilityTestsException()
            }
            //Update the info
            entry.repeatabilityFixNumberOfSentRequests = sender.sentRequests.size
            BurpExtender.ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.repeatabilityColumn)
            //Restore modified request first
            lastMessageInfo.clear()
            lastMessageInfo.add(SerializableHttpRequestResponse.fromHttpRequestResponse(entry.modifiedMessageInfo))
            entry.modifiedMessageInfo = SerializableHttpRequestResponse.fromHttpRequestResponse(entry.originalMessageInfo)
            //We can also reuse the hackvertor variables now
            entry.hackvertorVariable = 1
            //The detector reasons are also not accurate anymore, but if everything fails we want to show them
            allFails.addAll(detector.reasonsForFail)
        }
        return false
    }

    private fun getSingleStrategies(): List<Fixer> {
        val uuid = UuidValue(entry)
        val email = EmailValue(entry)
        val timestampMilliseconds = UnixTimestampMillisecondsValue(entry)
        val timestampSeconds = UnixTimestampSecondsValue(entry)
        val alphabetic = AlphabeticValue(entry)
        val boolean = BooleanValue(entry)
        val numeric = NumericValue(entry)
        val double = DoubleValue(entry)
        val charset = CharsetValue(entry)
        return listOf(
            //In comments we write ideas why repeating the same value might get you rejected by server or why to change
            uuid, //Client side set unique identifiers, very common
            email, //Admin interface with "add user" or registration form
            timestampMilliseconds, //All kind of JavaScript developer madness,
            // low false-positive rate as this is limited to values if now is 1651820430000 then:
            // 1644127220000 to 1659762020000, which is very specific +/- 3 months
            timestampSeconds, //All kind of JavaScript developer madness
            // low false-positive rate as this is limited to values if now is 1651820430 then:
            // 1644127220 to 1659762020, which is very specific +/- 3 months
            numeric, //Unique ID has to be unique
            alphabetic, //Username already exists rejections
            boolean, //"Overwrite flag", only if client says "overwrite" the server will delete the old value
            double, //Set a new price and old price can't be the same as the new price
            charset, //This covers all kind of cases you can think of
        )
    }

    private fun getCombinatoricStrategies(): List<List<Fixer>> {
        // These are just some "preferred" strategies...
        // Don't forget, at first *all* modifications of each fixer are applied. Then they are only combined.
        val uuid = UuidValue(entry)
        val email = EmailValue(entry)
        val timestampMilliseconds = UnixTimestampMillisecondsValue(entry)
        val timestampSeconds = UnixTimestampSecondsValue(entry)
        val alphabetic = AlphabeticValue(entry)
        val boolean = BooleanValue(entry)
        val numeric = NumericValue(entry)
        val double = DoubleValue(entry)
        val charset = CharsetValue(entry)
        val birthday = BirthdateValue(entry)
        val strategies = mutableListOf(
            //In comments we write ideas why repeating the same value might get you rejected by server or why to change
            listOf(uuid), //Client side set unique identifiers, very common
            listOf(email), //Admin interface with "add user" or registration form
            listOf(timestampMilliseconds), //All kind of JavaScript developer madness,
            // low false-positive rate as this is limited to values if now is 1651820430000 then:
            // 1644127220000 to 1659762020000, which is very specific +/- 3 months
            listOf(timestampSeconds), //All kind of JavaScript developer madness
            // low false-positive rate as this is limited to values if now is 1651820430 then:
            // 1644127220 to 1659762020, which is very specific +/- 3 months
            listOf(numeric), //Unique ID has to be unique
            listOf(alphabetic), //Username already exists rejections
            listOf(boolean), //"Overwrite flag", only if client says "overwrite" the server will delete the old value
            listOf(double), //Set a new price and old price can't be the same as the new price
            listOf(charset), //This covers all kind of cases you can think of
            listOf(uuid, email),
            listOf(uuid, timestampMilliseconds),
            listOf(uuid, timestampSeconds),
            listOf(uuid, email, boolean),
            listOf(uuid, email, timestampMilliseconds),
            listOf(uuid, email, timestampSeconds),
            listOf(uuid, email, numeric),
            listOf(uuid, email, boolean, numeric),
            listOf(uuid, email, boolean, numeric, double),
            listOf(boolean, numeric),
            listOf(email, numeric),
            listOf(email, boolean, numeric),

            listOf(uuid, alphabetic),
            listOf(email, alphabetic),
            listOf(uuid, email, alphabetic),
            listOf(uuid, email, numeric, alphabetic),
            listOf(numeric, alphabetic),
            listOf(email, numeric, alphabetic),

            listOf(uuid, boolean, alphabetic),
            listOf(email, boolean, alphabetic),
            listOf(uuid, email, boolean, alphabetic),
            listOf(boolean, alphabetic),
            listOf(uuid, email, boolean, numeric, alphabetic),
            listOf(boolean, numeric, alphabetic),
            listOf(email, numeric, boolean, alphabetic),
        )
        /*
        You might ask: Why is BirthdateValue not in the above list? Answer: There is probably not a lot of functionality
        that requires a different birthday in every request. The only one I can think of is a "change birthday" function
        where the new birthday can't be the already set birthday. Therefore this is only very late if at all a modification.
         */
        //But remove every "line" above where at least one of the approaches is not applicable
        strategies.removeAll{ strategy -> strategy.any { regexFixer -> !regexFixer.isEnabled() || regexFixer.noOfReplacementsEstimation() <= 0 } }
        // If we get to the last strategy, we test everything that leads to a change at all
        val all = mutableListOf(uuid, email, boolean, timestampMilliseconds, timestampSeconds, numeric, double,
            birthday, alphabetic, charset)
        all.removeAll{regexFixer -> !regexFixer.isEnabled() || regexFixer.noOfReplacementsEstimation() <= 0}
        strategies.add(all.toList())
        return strategies.toList()
    }

    private fun applyOneFullMatch() = sequence {
        for(fixer in getSingleStrategies()){
            if(BurpExtender.ui.settings.debug) {
                BurpExtender.println("")
                BurpExtender.println("## Strategy applyOneFullMatch: ${fixer.javaClass.name.split(".").last() }")
            }
            fixer.createReplacements()
            for(change in fixer.changesFullMatch){
                val theChange: MutableMap<String, List<String>> = mutableMapOf(change.key to change.value)
                fixer.makeModificationsFullMatch(theChange)
                yield(Modification(1, listOf("+" + fixer.reason)))
            }
        }
    }

    private fun applyAllFullMatch() = sequence {
        for(fixers in getCombinatoricStrategies()){
            if(BurpExtender.ui.settings.debug) {
                BurpExtender.println("")
                BurpExtender.println("## Strategy applyAllFullMatch: ${fixers.joinToString { it.javaClass.name.split(".").last() }}")
            }
            val reasons: MutableList<String> = mutableListOf()
            var totalNumberModifications = 0
            for(regexFixer in fixers){
                val noModifications = regexFixer.createReplacements()
                totalNumberModifications += noModifications
                //BurpExtender.println("Possible modifications for ${regexFixer.javaClass.name}: $noModifications")
                if(noModifications > 0){
                    reasons.add("+" + regexFixer.reason)
                    regexFixer.makeModificationsAllFullMatch()
                }
            }
            yield(Modification(totalNumberModifications, reasons))
        }
    }

    private fun applyCombinatoricFullMatch() = sequence {
        for(fixers in getCombinatoricStrategies()){
            if(BurpExtender.ui.settings.debug) {
                BurpExtender.println("")
                BurpExtender.println("## Strategy applyCombinatoricFullMatch: ${fixers.joinToString { it.javaClass.name.split(".").last() }}")
            }
            for(regexFixerCombination in combineRegexFixers(fixers)){
                val reasons: MutableList<String> = mutableListOf()
                var totalNumberModifications = 0
                for((regexFixer, combo) in regexFixerCombination){
                    val numberOfModifications = regexFixer.makeModificationsComboFullMatch(combo)
                    if(numberOfModifications > 0){
                        totalNumberModifications += numberOfModifications
                        reasons.add("+" + regexFixer.reason)
                    }
                }
                //if(BurpExtender.ui.settings.debug)
                //    BurpExtender.println("Combinatoric, trying: $totalNumberModifications with regexes ${regexFixerCombination.joinToString { it.first.javaClass.name }}")
                yield(Modification(totalNumberModifications, reasons))
            }
        }
    }

    private fun combineRegexFixers(fixers: List<Fixer>) = sequence {
        // Here the combinatoric gets more complicated... We don't only need to combine all combinations inside
        // one regexFixer (calculated as regexFixer.combinations), but all combinations of all regexFixer
        // So if the first regexFixer has 3 possible combinations:
        // [0, 1, 2]
        // And the second has 2 possible combinations:
        // [0, 1]
        // We need:
        // [[0, 0], [0, 1], [1, 0], [1, 1], [2, 0], [2, 1]]
        // That's what Combiner.combinationsOneEach does (cartesian product)
        // Btw. these are then only indexes for the combinations list inside a regexFixer...
        val inputs: MutableList<List<Int>> = mutableListOf()
        for(regexFixer in fixers){
            regexFixer.createReplacements()
            inputs.add((0 until regexFixer.combinationsFullMatch.size).toMutableList())
        }
        val allCombinations = Combiner.combinationsOneEach(inputs)
        for(combination in allCombinations){
            val thisComboFixers: MutableList<Pair<Fixer, List<Int>>> = mutableListOf()
            var regexFixerIndex = 0
            for(whichIndexForThisRegexFixer in combination){
                thisComboFixers.add(
                    Pair(
                        fixers[regexFixerIndex],
                        fixers[regexFixerIndex].combinationsFullMatch[whichIndexForThisRegexFixer]
                    )
                )
                regexFixerIndex += 1
            }
            yield(thisComboFixers.toList())
        }
    }
}

class Modification(
    val totalNumberModifications: Int = 0,
    val reasons: List<String> = listOf(),
)

class AbortRepeatabilityTestsException: Exception()