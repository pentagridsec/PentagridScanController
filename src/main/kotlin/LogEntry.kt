package ch.pentagrid.burpexts.pentagridscancontroller

import burpwrappers.RequestInfoAdvanced
import burpwrappers.SerializableHttpRequestResponse
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.ResponseInfoAdvanced
import java.io.*


data class LogEntry(
    var originalMessageInfo: SerializableHttpRequestResponse,
    var modifiedMessageInfo: SerializableHttpRequestResponse,
    var toolFlag: Int,
    var reasons: MutableSet<String>, //TODO: This should be a list, but at other places a Set, so that here we can get the same reason twice
    var wasScanned: Boolean = false,
    var duplicatesSeen: Int = 0,
    var interestingScore: Int = 0,
    var hidden: Boolean = false,
    var repeatabilityFixNumberOfSentRequests: Int = 0,
    var id: Int = 0
): Serializable{

    var hackvertorVariable: Int = 1

    override fun toString(): String {
        return "ID: $id, ToolFlag: $toolFlag, " +
                "Reasons: $reasons, Was scanned: $wasScanned, duplicatesSeen: $duplicatesSeen, " +
                "interestingScore: $interestingScore, hidden: $hidden, " +
                "repeatabilityFixNumberOfSentRequests: $repeatabilityFixNumberOfSentRequests, " +
                "hackvertorVariable: $hackvertorVariable"
    }

    val originalRequestInfo: RequestInfoAdvanced
        get() = BurpExtender.h.analyzeRequest(originalMessageInfo)

    val originalResponseInfo: ResponseInfoAdvanced
        get() = BurpExtender.h.analyzeResponse(originalMessageInfo.response!!)

    val modifiedRequestInfo: RequestInfoAdvanced
        get() = BurpExtender.h.analyzeRequest(modifiedMessageInfo)

    val modifiedResponseInfo: ResponseInfoAdvanced
        get() = BurpExtender.h.analyzeResponse(modifiedMessageInfo.response!!)

}