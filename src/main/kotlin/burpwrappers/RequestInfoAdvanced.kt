package burpwrappers

import burp.IParameter
import burp.IRequestInfo
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.boundaryMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.charsetDelimiter
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentDispositionMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentDispositonValueDelimiter
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentDispositonValueFilenameData
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentDispositonValueFormData
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentLengthMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentTypeMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.doubleDash
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.headerDelimiter
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.knownHttpHeadersLower
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.newline
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.spaceStatusLineDelimiter
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders.*


open class RequestInfoAdvanced(override val requestInfo: IRequestInfo, override val request: ByteArray) : IRequestInfo by requestInfo,
    IRequestInfoAdvanced {

    override val parameters: List<ParameterAdvanced>
        get() {
            val list = mutableListOf<ParameterAdvanced>()
            var hasJson = false
            var hasXml = false
            var hasMultipart = false
            for(p in requestInfo.parameters){
                when (p.type) {
                    IParameter.PARAM_URL -> {
                        list.add(UrlParameter(p))
                    }
                    IParameter.PARAM_BODY -> {
                        list.add(BodyParameter(p))
                    }
                    IParameter.PARAM_COOKIE -> {
                        list.add(CookieParameter(p))
                    }
                    IParameter.PARAM_XML -> {
                        hasXml = true
                    }
                    IParameter.PARAM_XML_ATTR -> {
                        hasXml = true
                    }
                    IParameter.PARAM_JSON -> {
                        hasJson = true
                    }
                    IParameter.PARAM_MULTIPART_ATTR -> {
                        hasMultipart = true
                    }
                    else -> {
                        //Unknown Parameter
                        BurpExtender.println("Unknown parameter type ${p.type}")
                        //list.add(p)
                    }
                }
            }
            if(hasJson)
                //We don't want list and dictionaries from json, but only "leaves", so noComplex=true is fine
                list.addAll(JsonBuilder(bodyString).getParameters())
            if(hasXml)
                list.addAll(XmlBuilder(bodyString).getParameters())
            if(hasMultipart)
                list.addAll(MultipartBuilder(request).getParameters())
            list.addAll(NonStandardHeaderBuilder(request).getParameters())
            list.addAll(UrlPathBuilder(relativeUrl).getParameters())
            return list
        }

    override val statusLine
    get(): String {
        return headers[0]
    }

    override val relativeUrl
    get(): String {
        return statusLine.split(spaceStatusLineDelimiter).drop(
            1).dropLast(1).joinToString(spaceStatusLineDelimiter)
    }

    //Do not mix this up with url.file, which is url.path + url.query
    //Whereas this is the name of the file in the path (e.g. "example.php")
    override val urlNameOfFileInPath
    get(): String {
        return url?.path?.split("/")?.last() ?: ""
    }

    //e.g. ".php"
    override val fileExtension
        get(): String {
            if("." in urlNameOfFileInPath)
                return urlNameOfFileInPath.split(".").last()
            return ""
        }

    override val httpVersion
    get(): String {
        return statusLine.split(spaceStatusLineDelimiter).last()
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
        return try {
            headers.drop(1).first { it.startsWith(contentTypeMarker, true) }
        }catch(e: NoSuchElementException){
            null
        }
    }

    override val headerBytes
        get(): ByteArray {
            return request.take(bodyOffset).toByteArray()
        }

    override val bodyBytes
    get(): ByteArray {
        return request.drop(bodyOffset).toByteArray()
    }

    override val bodyString
    get(): String {
        return BurpExtender.h.bytesToString(bodyBytes)
    }

    override val hostnamePort
    get(): String {
        return url!!.host + ":" + url!!.port
    }

    override fun createNewRelativeUrl(relativeUrl: String): ByteArray{
        return BurpExtender.h.stringToBytes(
            "$method $relativeUrl $httpVersion$newline" +
                headers.drop(1).joinToString(newline) + newline + newline
        ) + bodyBytes
    }

    override fun createNewHeaders(headersList: List<Pair<String, String>>): ByteArray{
        return BurpExtender.h.stringToBytes(
            "$statusLine$newline" +
                    headersList.joinToString(newline) { it.first + headerDelimiter + it.second } + newline + newline
        ) + bodyBytes
    }


    /*
POST /test?foo=bar& HTTP/1.1
Host: 127.0.0.1
Content-Length: 1337
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryExample

------WebKitFormBoundaryExample
Content-Disposition: form-data; name="whatever"

other
------WebKitFormBoundaryExample
Content-Disposition: form-data; name="paramname"; filename="up.jpeg"
Content-Type: application/pdf

[file contents here]
------WebKitFormBoundaryExample--
 */

    // Content-Type: multipart/form-data; charset=utf-8; boundary="boundary"
    // Unknown if allowed by spec but also properly handled:
    // Content-Type: multipart/form-data; boundary="boundary"; charset=utf-8

    override val isMultipart
        get(): Boolean{
            return contentTypeHeader?.contains(IRequestInfoAdvanced.multipartContentType) ?: false
        }

    //Multipart things
    override val multipartBoundary
        get(): String{
            return doubleDash + (contentTypeHeader?.substringAfter(boundaryMarker)?.substringBefore(charsetDelimiter)
                ?: "")
        }

    override val multiparts
        get(): List<String>{
            //cut off ending boundary (and implicitly the newline after it)
            val body = bodyString.split(newline + multipartBoundary + doubleDash)[0]
            val parts = (newline + body).split(newline + multipartBoundary + newline)
            return parts.drop(1)
        }

    override fun multipartHeadersFromFileIndex(fileIndex: Int): List<String>{
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartHeaders(multipartIndex)
    }

    override fun multipartHeaders(index: Int): List<String>{
        return multiparts[index].split(newline + newline)[0].split(newline)
    }

    override fun multipartHeaders(multipart: String): List<String>{
        return multipart.split(newline + newline)[0].split(newline)
    }

    override fun multipartBodyFromFileIndex(fileIndex: Int): String{
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartBody(multipartIndex)
    }

    override fun multipartBody(index: Int): String {
        return multipartBody(multiparts[index])
    }

    override fun multipartBody(multipart: String): String {
        //Aka upload content
        val contentWithNewline = multipart.split(newline + newline, limit = 2)[1]
        //The last newline is the one before the next boundary, which are not part of the file content
        //TODO: I assume this removeSuffix is unnecessary, test!
        return contentWithNewline.removeSuffix(newline)
    }

    override fun multipartContentTypeHeaderFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartContentTypeHeader(multipartIndex)
    }

    override fun multipartContentTypeHeader(index: Int): String {
        return multipartHeaders(index).first { it.startsWith(contentTypeMarker, true) }
    }

    override fun multipartContentTypeFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartContentType(multipartIndex)
    }

    override fun multipartContentType(index: Int): String{
        return multipartContentTypeHeader(index).drop(contentTypeMarker.length)
    }

    override fun multipartContentDispositionHeaderFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartContentDispositionHeader(multipartIndex)
    }

    override fun multipartContentDispositionHeader(index: Int): String {
        return multipartHeaders(index).first { it.startsWith(contentDispositionMarker, true) }
    }

    override fun multipartContentDispositionHeader(multipart: String): String {
        return multipartHeaders(multipart).first { it.startsWith(contentDispositionMarker, true) }
    }

    override fun multipartContentDispositionFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartContentDisposition(multipartIndex)
    }

    override fun multipartContentDisposition(index: Int): String{
        return multipartContentDispositionHeader(index).drop(contentDispositionMarker.length)
    }

    override fun multipartContentDisposition(multipart: String): String{
        return multipartContentDispositionHeader(multipart).drop(contentDispositionMarker.length)
    }

    override fun multipartFilenameFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartFilename(multipartIndex)
    }

    override fun multipartFilename(index: Int): String {
        return multipartFilename(multiparts[index])
    }

    override fun multipartFilename(multipart: String): String {
        val cdHeader = multipartContentDisposition(multipart)
        var filenameEnd = cdHeader.split(contentDispositonValueFilenameData, limit=2)[1]
        if(filenameEnd.endsWith(contentDispositonValueDelimiter)){
            filenameEnd = filenameEnd.removeSuffix(contentDispositonValueDelimiter)
        }
        return filenameEnd
    }

    override fun multipartParameternameFromFileIndex(fileIndex: Int): String {
        val multipartIndex = multipartFileIndexToMultipartIndex(fileIndex)
        return multipartParametername(multipartIndex)
    }

    override fun multipartParametername(index: Int): String {
        return multipartParametername(multiparts[index])
    }

    override fun multipartParametername(multipart: String): String {
        val cdHeader = multipartContentDisposition(multipart)
        val parameternameEnd = cdHeader.split(contentDispositonValueFormData, limit=2)[1]
        return if(cdHeader.contains(contentDispositonValueFilenameData)) {
            parameternameEnd.split(contentDispositonValueFilenameData, limit = 2)[0]
        }else{
            parameternameEnd.split(contentDispositonValueDelimiter, limit = 2)[0]
        }
    }

    override val multipartNumberOfFiles
        get(): Int{
            var seenFilenameContentDispositions = 0
            for (index in multiparts.indices) {
                if (isFileMultipart(index)) {
                    seenFilenameContentDispositions++
                }
            }
            return seenFilenameContentDispositions
        }

    override fun multipartFileIndexToMultipartIndex(fileIndex: Int): Int{
        /*
        Which multipart index is the one that has the file upload? In general an easy question two answer,
        it's the one that has the following header:
        Content-Disposition: form-data; name="paramname"; filename="up.jpeg"
        However, what if there are two of these and the user uploads two files (or more) at the same time?
        That's why we take fileIndex in the constructor. fileIndex = 0 means the first file, 1 = second file, etc.
        */
        var seenFilenameContentDispositions = 0
        for (index in multiparts.indices) {
            if (isFileMultipart(index)) {
                if (seenFilenameContentDispositions == fileIndex) {
                    return index
                }
                else{
                    seenFilenameContentDispositions++
                }
            }
        }
        return -1
    }

    override fun multipartMultipartIndexToFileIndex(index: Int): Int {
        var seenFilenameContentDispositions = 0
        for (indexCounter in multiparts.indices) {
            if (isFileMultipart(indexCounter)) {
                if (indexCounter == index) {
                    return seenFilenameContentDispositions
                }
                else{
                    seenFilenameContentDispositions++
                }
            }
        }
        return -1
    }

    override fun isFileMultipart(index: Int): Boolean {
        val cdHeader = multipartContentDisposition(index)
        return (cdHeader.contains(contentDispositonValueFormData) &&
                cdHeader.contains(contentDispositonValueFilenameData))
    }

    override fun isFileMultipart(multipart: String): Boolean {
        val cdHeader = multipartContentDisposition(multipart)
        return (cdHeader.contains(contentDispositonValueFormData) &&
                cdHeader.contains(contentDispositonValueFilenameData))
    }

    override fun createNewMultipart(index: Int, name: String?, filename: String?, content: String?): String{
        return createNewMultipart(multiparts[index], name, filename, content)
    }

    override fun createNewMultipart(multipart: String, name: String?, filename: String?, content: String?): String{
        val newName = name?:multipartParametername(multipart)
        val newContent = content?:multipartBody(multipart)
        var newFilename = filename
        if(newFilename == null){
            if(isFileMultipart(multipart)){
                newFilename = multipartFilename(multipart)
            }
        }
        var newMultipart = contentDispositionMarker + contentDispositonValueFormData + newName
        if(newFilename != null){
            newMultipart += contentDispositonValueFilenameData + newFilename
        }
        newMultipart += contentDispositonValueDelimiter + newline
        newMultipart += multipartHeaders(multipart).filter { !it.startsWith(contentDispositionMarker) }
            .joinToString(newline)
        newMultipart += newline + newline + newContent
        return newMultipart
    }

    override fun createMultipartBody(multiparts: List<String>): String{
        var body = multipartBoundary + newline
        body += multiparts.joinToString(newline + multipartBoundary + newline)
        body += newline + multipartBoundary + doubleDash + newline
        return body
    }


}