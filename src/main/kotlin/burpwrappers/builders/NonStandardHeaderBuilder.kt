package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*


class NonStandardHeaderBuilder(private val request: ByteArray){

    //TODO FEATURE: Use non standard headers as an InsertionPoint for Burp

    fun getParameters(): List<NonStandardHeaderParameter> {
        val requestInfo = BurpExtender.h.analyzeRequest(request)
        val params: MutableList<NonStandardHeaderParameter> = mutableListOf()
        val headers: List<Pair<String, String>> = requestInfo.nonStandardHeaders
        for ((name, value) in headers) {
            params.add(NonStandardHeaderParameter(name, value))
        }
        return params
    }

    fun setParameter(h: NonStandardHeaderParameter): ByteArray {
        val requestInfo = BurpExtender.h.analyzeRequest(request)
        val headers: MutableList<Pair<String, String>> = requestInfo.headersList.toMutableList()
        for(index in headers.indices){
            if(headers[index].first.lowercase() == h.name!!.lowercase()){
                val newPair = Pair(headers[index].first, h.value)
                headers[index] = newPair
                //We shouldn't break here, because what if there are two times the same header?
                //break
            }
        }
        return requestInfo.createNewHeaders(headers)
    }
}