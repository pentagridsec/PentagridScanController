package ch.pentagrid.burpexts.pentagridscancontroller

import burpwrappers.SerializableHttpRequestResponse
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.Md5Set

class RepeaterSender(val entry: LogEntry) {

    val sentRequests: Md5Set = Md5Set() //Only stores MD5 values of requests
    var pureCounter: Int = 0

    fun repeatIfNotAlready(fixContentLength: Boolean = true): Boolean {
        pureCounter += 1
        if(fixContentLength)
            entry.modifiedMessageInfo.request = BurpExtender.h.fixContentLength(entry.modifiedMessageInfo.request)
        if(!sentRequests.contains(entry.modifiedMessageInfo.request)){
            sentRequests.add(entry.modifiedMessageInfo.request)
            //Now actually send the request
            val requestWithHackvertor = entry.modifiedMessageInfo.request
            val effectivelySent = BurpExtender.c.makeHttpRequest(entry.modifiedMessageInfo.httpService, entry.modifiedMessageInfo.request)
            entry.modifiedMessageInfo = SerializableHttpRequestResponse.fromHttpRequestResponse(effectivelySent)
            entry.modifiedMessageInfo.request = requestWithHackvertor
            return true
        }
        return false
    }
}