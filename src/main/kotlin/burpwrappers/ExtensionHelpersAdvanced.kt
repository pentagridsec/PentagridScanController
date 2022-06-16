package burpwrappers

import burp.*
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.IRequestInfoAdvanced.Companion.contentLengthMarker
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.ResponseInfoAdvanced
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders.*
import ch.pentagrid.burpexts.pentagridscancontroller.extensionName
import javax.swing.JTabbedPane


class ExtensionHelpersAdvanced(val helper: IExtensionHelpers) : IExtensionHelpers by helper {

    fun isHackvertorLoaded(ui: ITab): Boolean{
        //taken from https://github.com/hackvertor/taborator/blob/master/src/main/java/burp/BurpExtender.java#L692
        val parent = ui.uiComponent.parent as JTabbedPane?
        if(parent == null){
            BurpExtender.println("Parent is null, probably this extension was already unloaded again...")
            return true
        }
        for (i in 0 until parent.tabCount) {
            if (parent.getTitleAt(i).contains("Hackvertor")) {
                return true
            }
        }
        return false
    }

    fun isHackvertorUsable(): Boolean{
        // Might return true although Hackvertor is not usable
        // If you don't have a Collaborator, this function will send requests to example.org!
        val req: ByteArray
        val workingReq: ByteArray
        val port: Int = 443
        val useHttps: Boolean = true
        var host = BurpExtender.c.createBurpCollaboratorClientContext()?.generatePayload(true)

        if(host != null){
            //Returns 200 if Hackvertor is working
            //Times-out if Hackvertor is not working
            if(host.contains("/")){
                //Burp Collaborator with IP
                val splitted = host.split("/", limit = 1)
                host = splitted[0]
                val urlPath = splitted[1]
                req = BurpExtender.h.stringToBytes("GET /$urlPath HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "Extension: $extensionName testing if Hackvertor works<@d_url>%0D%0A%0D%0A<@/d_url>")
                workingReq = BurpExtender.h.stringToBytes("GET /$urlPath HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "Extension: $extensionName testing if Hackvertor works\r\n\r\n")
            }else{
                req = BurpExtender.h.stringToBytes("GET / HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "Extension: $extensionName testing if Hackvertor works<@d_url>%0D%0A%0D%0A<@/d_url>")
                workingReq = BurpExtender.h.stringToBytes("GET / HTTP/1.1\r\n" +
                        "Host: $host\r\n" +
                        "Extension: $extensionName testing if Hackvertor works\r\n\r\n")
            }
        }else{
            //Returns 200 if Hackvertor is working
            //Returns 400 if Hackvertor is not working
            host = "example.org"
            req = BurpExtender.h.stringToBytes(
                "GET / HTTP/1.1\r\n" +
                        "Host: <@d_url><@urlencode_all>example.org<@/urlencode_all><@/d_url>\r\n" +
                        "\r\n")
            workingReq = BurpExtender.h.stringToBytes(
                "GET / HTTP/1.1\r\n" +
                        "Host: example.org\r\n" +
                        "\r\n")
        }
        // First check if we have Internet connection by sending a request that returns 200
        val workingResponse = BurpExtender.c.makeHttpRequest(host, port, useHttps, workingReq)
        return if(workingResponse == null || BurpExtender.h.analyzeResponse(workingResponse).statusCode != 200.toShort()){
            // Working request is not working. That could just mean:
            // - We don't have Internet connection
            // - example.org or Burp Collaborator is down
            // But that doesn't mean Hackvertor is not working...
            true
        }else {
            val respo = BurpExtender.c.makeHttpRequest(host, port, useHttps, req)
            respo != null && BurpExtender.h.analyzeResponse(respo).statusCode == 200.toShort()
        }
    }

    fun fixContentLength(request: ByteArray): ByteArray{
        val requestInfo = BurpExtender.h.analyzeRequest(request)
        val headers = requestInfo.headers
        val statusLine = BurpExtender.h.stringToBytes(headers[0])
        val newHeaders: MutableList<String> = mutableListOf()
        val body = request.drop(requestInfo.bodyOffset)
        val bodyLength = body.size
        var found = false
        for(header in headers.drop(1)){
            if(header.lowercase().startsWith(contentLengthMarker.lowercase())){
                newHeaders.add(header.take(contentLengthMarker.length) + bodyLength)
                found = true
            }
            else{
                newHeaders.add(header)
            }
        }
        if(!found){
            newHeaders.add(contentLengthMarker + bodyLength)
        }
        return statusLine + "\r\n".toByteArray() +
                BurpExtender.h.stringToBytes(newHeaders.joinToString("\r\n")) + "\r\n\r\n".toByteArray() +
                body
    }

    override fun analyzeRequest(httpService: IHttpService, request: ByteArray): RequestInfoAdvanced {
        return RequestInfoAdvanced(helper.analyzeRequest(httpService, request), request)
    }

    override fun analyzeRequest(request: ByteArray): RequestInfoAdvanced {
        return RequestInfoAdvanced(helper.analyzeRequest(request), request)
    }

    override fun analyzeRequest(request: IHttpRequestResponse): RequestInfoAdvanced {
        return RequestInfoAdvanced(helper.analyzeRequest(request), request.request)
    }

    override fun analyzeResponse(response: ByteArray): ResponseInfoAdvanced {
        return ResponseInfoAdvanced(helper.analyzeResponse(response), response)
    }

    fun buildParameter(oldParameter: IParameter, name: String? = oldParameter.name,
                       value: String = oldParameter.value): IParameter{
        /*
        Burp Supports:
        PARAM_BODY Used to indicate a parameter within the message body.
        PARAM_COOKIE Used to indicate an HTTP cookie.
        PARAM_URL Used to indicate a parameter within the URL query string.

        We support in custom code:
        PARAM_JSON Used to indicate an item of data within a JSON structure.
        PARAM_MULTIPART_ATTR Used to indicate the value of a parameter attribute within a multi-part message body (such as the name of an uploaded file).
        PARAM_XML Used to indicate an item of data within an XML structure.
        PARAM_XML_ATTR Used to indicate the value of a tag attribute within an XML structure.

        We created because Burp didn't even consider yet:
        PARAM_URL_PATH Used to indicate an item of the path of the URL (including the filename itself without query string).
        PARAM_NON_STANDARD_HEADER Used to indicate a HTTP request header that is not in the knownHttpHeaders list
        */
        return if((PARAM_JSON_NULL <= oldParameter.type) && (oldParameter.type <= PARAM_JSON_DICT)) {
            val j = (oldParameter as JsonParameter)
            oldParameter.name = name
            j.value = value
            j
        } else if(oldParameter.type == PARAM_XML_CONTENT || oldParameter.type == PARAM_XML_ATTR) {
            val j = (oldParameter as XmlParameter)
            //TODO FEATURE: We don't support changing XML parameter names
            //oldParameter.name = name
            j.value = value
            j
        } else if(oldParameter.type == PARAM_URL_PATH_TYPE){
            val u = (oldParameter as UrlPathParameter)
            u.value = value
            u
        } else if(oldParameter.type == PARAM_MULTIPART_CONTENT || oldParameter.type == PARAM_MULTIPART_FILENAME){
            val m = (oldParameter as MultipartParameter)
            m.name = name
            m.value = value
            m
        } else if(oldParameter.type == PARAM_NON_STANDARD_HEADER_TYPE){
            val m = (oldParameter as NonStandardHeaderParameter)
            m.name = name
            m.value = value
            m
        }else {
            helper.buildParameter(name?:"", value, oldParameter.type)
        }
    }

    override fun buildParameter(name: String, value: String, type: Byte): IParameter{
        return helper.buildParameter(name, value, type)
    }

    override fun updateParameter(request: ByteArray, parameter: IParameter): ByteArray {
        //BurpExtender.println("Parameter type: ${Integer.toHexString(parameter.type.toInt())}, name ${parameter.name}, " +
        //        "value ${parameter.value}")
        //TODO BURP LIMITATION: What if an XML is base64 encoded in the body? Do we still get it? Then it wouldn't just
        //be the body of the request... unclear.
        return if((PARAM_JSON_NULL <= parameter.type) && (parameter.type <= PARAM_JSON_DICT)){
            val requestInfo = BurpExtender.h.analyzeRequest(request)
            val headers = requestInfo.headerBytes
            val newBody = BurpExtender.h.stringToBytes(JsonBuilder(requestInfo.bodyString).setParameter(parameter as JsonParameter))
            headers + newBody
        } else if(parameter.type == PARAM_XML_ATTR || parameter.type == PARAM_XML_CONTENT){
            val requestInfo = BurpExtender.h.analyzeRequest(request)
            val headers = requestInfo.headerBytes
            val newBody = BurpExtender.h.stringToBytes(XmlBuilder(requestInfo.bodyString).setParameter(parameter as XmlParameter))
            headers + newBody
        } else if(parameter.type == PARAM_URL_PATH_TYPE){
            val requestInfo = BurpExtender.h.analyzeRequest(request)
            val newRelativeUrl = UrlPathBuilder(requestInfo.relativeUrl).setParameter(parameter as UrlPathParameter)
            requestInfo.createNewRelativeUrl(newRelativeUrl)
        } else if(parameter.type == PARAM_MULTIPART_CONTENT || parameter.type == PARAM_MULTIPART_FILENAME){
            MultipartBuilder(request).setParameter(parameter as MultipartParameter)
        } else if(parameter.type == PARAM_NON_STANDARD_HEADER_TYPE){
            NonStandardHeaderBuilder(request).setParameter(parameter as NonStandardHeaderParameter)
        } else {
            helper.updateParameter(request, parameter)
        }
    }

    override fun addParameter(request: ByteArray, parameter: IParameter): ByteArray {
        return helper.addParameter(request, parameter)
    }

    override fun removeParameter(request: ByteArray, parameter: IParameter): ByteArray {
        return helper.removeParameter(request, parameter)
    }

}