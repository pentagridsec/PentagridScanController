package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*


class MultipartBuilder(private val request: ByteArray){

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

    fun getParameters(): List<MultipartParameter> {
        val requestInfo = BurpExtender.h.analyzeRequest(request)
        val params: MutableList<MultipartParameter> = mutableListOf()
        if(requestInfo.isMultipart) {
            for (multipartIndex in requestInfo.multiparts.indices) {
                val name = requestInfo.multipartParametername(multipartIndex)
                if (requestInfo.isFileMultipart(multipartIndex)) {
                    val filename = requestInfo.multipartFilename(multipartIndex)
                    params.add(MultipartFilename(name, filename, multipartIndex))
                }
                val content = requestInfo.multipartBody(multipartIndex)
                params.add(MultipartContent(name, content, multipartIndex))
            }
        }
        return params
    }

    fun setParameter(m: MultipartParameter): ByteArray {
        val requestInfo = BurpExtender.h.analyzeRequest(request)
        val multiparts = requestInfo.multiparts.toMutableList()
        if(m is MultipartFilename) {
            // Pass the value as the filename
            multiparts[m.multipartIndex] = requestInfo.createNewMultipart(m.multipartIndex, m.name, m.value, null)
        }else if(m is MultipartContent){
            // Pass the value as the content
            multiparts[m.multipartIndex] = requestInfo.createNewMultipart(m.multipartIndex, m.name, null, m.value)
        }

        return requestInfo.headerBytes + BurpExtender.h.stringToBytes(requestInfo.createMultipartBody(multiparts))
    }


}
