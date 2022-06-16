package burpwrappers

import burp.IHttpRequestResponse
import burp.IHttpService
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import java.io.Serializable

data class SerializableHttpRequestResponse(
    override var request: ByteArray, override var response: ByteArray?, override var comment: String?,
    override var highlight: String?, override var httpService: IHttpService
): IHttpRequestResponse, Serializable {

    companion object{
        fun fromHttpRequestResponse(rr: IHttpRequestResponse): SerializableHttpRequestResponse{
            return SerializableHttpRequestResponse(rr.request.clone(), rr.response, rr.comment, rr.highlight,
                SerializableHttpService.fromHttpService(rr.httpService))
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as SerializableHttpRequestResponse

        if (!request.contentEquals(other.request)) return false
        if (response != null) {
            if (other.response == null) return false
            if (!response.contentEquals(other.response)) return false
        } else if (other.response != null) return false
        if (comment != other.comment) return false
        if (highlight != other.highlight) return false
        if (httpService != other.httpService) return false

        return true
    }

    override fun hashCode(): Int {
        var result = request.contentHashCode()
        result = 31 * result + (response?.contentHashCode() ?: 0)
        result = 31 * result + (comment?.hashCode() ?: 0)
        result = 31 * result + (highlight?.hashCode() ?: 0)
        result = 31 * result + httpService.hashCode()
        return result
    }

    val requestString: String
        get() = BurpExtender.h.bytesToString(request)

    val responseString: String?
        get() = response?.let { BurpExtender.h.bytesToString(it) }

}