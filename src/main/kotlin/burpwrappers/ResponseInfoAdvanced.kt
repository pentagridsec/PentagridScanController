package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers

import burp.IResponseInfo
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentLengthMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentTypeMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.headerDelimiter
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.knownHttpHeadersLower
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.spaceStatusLineDelimiter


open class ResponseInfoAdvanced(override val responseInfo: IResponseInfo, override val response: ByteArray) : IResponseInfo by responseInfo,
    IResponseInfoAdvanced {

    override val statusLine
    get(): String {
        return headers[0]
    }

    override val httpVersion
    get(): String {
        return statusLine.split(spaceStatusLineDelimiter, limit = 3)[0]
    }

    override val statusCode
        get(): Short {
            return statusLine.split(spaceStatusLineDelimiter, limit = 3)[1].toShort()
        }

    override val headersList
        get(): List<Pair<String, String>> {
            return headers.drop(1).map {
                val x = it.split(headerDelimiter, limit = 2)
                Pair(x[0], x[1])
            }
        }

    override val nonStandardHeaders
        get(): List<Pair<String, String>> {
            return headersList.filter{! knownHttpHeadersLower.contains(it.first.lowercase())}
        }

    override val contentLengthHeader
        get(): String {
            return headers.drop(1).first { it.startsWith(contentLengthMarker, true) }
        }

    override val contentLength
        get(): Int {
            return contentLengthHeader.split(headerDelimiter, limit = 2)[1].toInt()
        }

    override val contentTypeHeader
    get(): String? {
        try {
            return headers.drop(1).first { it.startsWith(contentTypeMarker, true) }
        }catch(e: NoSuchElementException){
            return null
        }
    }

    override val headerBytes
        get(): ByteArray {
            return response.take(bodyOffset).toByteArray()
        }

    override val bodyBytes
    get(): ByteArray {
        return response.drop(bodyOffset).toByteArray()
    }

    override val bodyString
    get(): String {
        return BurpExtender.h.bytesToString(bodyBytes)
    }

}