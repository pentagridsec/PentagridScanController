package ch.pentagrid.burpexts.pentagridscancontroller

class RepeatableDetector(val sender: RepeaterSender, val entry: LogEntry) {

    var reasonsForFail: MutableList<String> = mutableListOf()
    var reasonsForSuccess: MutableList<String> = mutableListOf()
    var fatal: Int = 0

    fun isLookingRepeatable(fixContentLength: Boolean = true): Boolean{
        reasonsForFail.clear()
        reasonsForSuccess.clear()
        val repeated = sender.repeatIfNotAlready(fixContentLength)
        if(repeated) {
            //if(BurpExtender.ui.settings.debug)
            //    BurpExtender.println("Sent request!")
            val response = entry.modifiedMessageInfo.responseString ?: return false
            if(BurpExtender.ui.settings.fixedResponse.isNotEmpty()){
                return if(response.contains(BurpExtender.ui.settings.fixedResponse)) {
                    reasonsForSuccess.add("+User defined fixed response")
                    true
                }else{
                    reasonsForFail.add("-User defined fixed response")
                    false
                }
            }
            val repeatableStatusCode = entry.modifiedResponseInfo.statusCode == entry.originalResponseInfo.statusCode
            return if (BurpExtender.ui.settings.ignoreHttpStatusCodeWhenDecidingRepeatability) {
                reasonsForSuccess.add("+ignore status code")
                isLookingRepeatableHeuristics()
            } else if (repeatableStatusCode) {
                reasonsForSuccess.add("+status code")
                isLookingRepeatableHeuristics()
            } else {
                reasonsForFail.add("-status code")
                return false
            }
        }
        else{
            if(BurpExtender.ui.settings.debug)
                BurpExtender.println("We already had this request before, didn't send again")
            return false
        }
    }

    private fun isLookingRepeatableHeuristics(): Boolean{
        //Seen in the wild in response json bodies:
        //{"status":200,"data":""}
        val origResp = entry.originalMessageInfo.responseString
        val modResp = entry.modifiedMessageInfo.responseString
        if (origResp == null || modResp == null) {
            return false
        } else {
            if(BurpExtender.ui.settings.useHeuristics){
                if(BurpExtender.ui.settings.heuristicResponseLengthPercent < 100){
                    //This heuristic could probably fail if your Fixers don't inject same length stuff,
                    //but they usually do
                    //Also, only apply this if the response body is at least 100 characters long, because
                    //Otherwise that doesn't make much sense
                    val origSize = entry.originalResponseInfo.bodyBytes.size
                    val modifiedSize = entry.modifiedResponseInfo.bodyBytes.size
                    if(origSize >= 100){
                        val diff = if(origSize > modifiedSize){
                            ((origSize.toDouble() / modifiedSize) - 1) * 100
                        }
                        else{
                            ((modifiedSize.toDouble() / origSize) - 1) * 100
                        }
                        if(diff > BurpExtender.ui.settings.heuristicResponseLengthPercent){
                            reasonsForFail.add("-${diff.toInt()}% length")
                            return false
                        }
                    }
                }
                val origReqClean2 = clean2(entry.originalMessageInfo.requestString)
                val origRespClean2 = clean2(origResp)
                val modReqClean2 = clean2(entry.modifiedMessageInfo.requestString)
                val modRespClean2 = clean2(modResp)
                //status:200 and such things
                for(variant in BurpExtender.ui.settings.heuristicWordsSuccess.map{clean2(it)}) {
                    if (origRespClean2.contains(variant)) {
                        if (modRespClean2.contains(variant)) {
                            reasonsForSuccess.add("+Heuristic: '${variant}'")
                        }else{
                            //So it seems we had status=200 in original response, but not in the modified response
                            //Now also check that it isn't just a "reflected" thing, checking if the same was
                            //in original *request* but not in the modified *request*
                            if(origReqClean2.contains(variant) &&
                                !modReqClean2.contains(variant)){
                                //This could be just a false-positive because the original request had
                                //status=200 which was reflected in the response,
                                //whereas the modified request did not have status=200 in it. Therefore, let's
                                //not count this cornercase
                            }else {
                                reasonsForFail.add("-Heuristic: '${variant}'")
                                return false
                            }
                        }
                    }
                }
                val origReqClean = clean(entry.originalMessageInfo.requestString)
                val origRespClean = clean(origResp)
                val modReqClean = clean(entry.modifiedMessageInfo.requestString)
                val modRespClean = clean(modResp)
                //Exception and such things
                val errorsAndFatal = BurpExtender.ui.settings.heuristicWordsError.map{clean(it)}.toMutableList()
                val fatal = BurpExtender.ui.settings.heuristicWordsFatal.map{clean(it)}
                errorsAndFatal.addAll(fatal)
                for(variant in errorsAndFatal) {
                    if(!origRespClean.contains(variant) && modRespClean.contains(variant)) {
                        //So it seems we have an error-indicating word in the modified response, which we didn't
                        //have in the original one
                        if(!origReqClean.contains(variant) && modReqClean.contains(variant)){
                            //This is probably just a false-positive because the original request had
                            //no such word in it, but the modified request had
                        }else {
                            if(fatal.contains(variant)){
                                reasonsForFail.add("-Heuristic fatal: '${variant}'")
                                this.fatal += 1
                            }else{
                                reasonsForFail.add("-Heuristic error: '${variant}'")
                            }
                            return false
                        }
                    }
                }
            }
        }
        reasonsForSuccess.add("+Heuristics passed")
        return true
    }

    private fun clean(s: String): String {
        return s.lowercase()
    }

    private fun clean2(s: String): String {
        return clean(s).replace(" ", "")
    }
}
