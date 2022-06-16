package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers

import burp.IResponseInfo

interface IResponseInfoAdvanced: IResponseInfo {

    val responseInfo: IResponseInfo
    val response: ByteArray
    val statusLine: String
    val httpVersion: String
    val contentLengthHeader: String
    val contentLength: Int
    val contentTypeHeader: String?
    val headerBytes: ByteArray
    val bodyBytes: ByteArray
    val bodyString: String
    val headersList: List<Pair<String, String>>
    val nonStandardHeaders: List<Pair<String, String>>
}