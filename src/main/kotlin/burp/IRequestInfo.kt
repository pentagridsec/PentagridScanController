package burp

/*
 * @(#)IRequestInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.URL

/**
 * This interface is used to retrieve key details about an HTTP request.
 * Extensions can obtain an
 * `IRequestInfo` object for a given request by calling
 * `IExtensionHelpers.analyzeRequest()`.
 */
interface IRequestInfo {

    /**
     * This method is used to obtain the HTTP method used in the request.
     *
     * @return The HTTP method used in the request.
     */
    val method: String

    /**
     * This method is used to obtain the URL in the request.
     *
     * @return The URL in the request.
     */
    val url: URL?

    /**
     * This method is used to obtain the HTTP headers contained in the request.
     * It includes the status line.
     *
     * @return The HTTP headers contained in the request.
     */
    var headers: List<String>

    /**
     * This method is used to obtain the parameters contained in the request.
     *
     * @return The parameters contained in the request.
     */
    val parameters: List<IParameter>

    /**
     * This method is used to obtain the offset within the request where the
     * message body begins.
     *
     * @return The offset within the request where the message body begins.
     */
    val bodyOffset: Int

    /**
     * This method is used to obtain the content type of the message body.
     *
     * @return An indication of the content type of the message body. Available
     * types are defined within this interface.
     */
    val contentType: Byte

    companion object {
        /**
         * Used to indicate that there is no content.
         */
        const val CONTENT_TYPE_NONE: Byte = 0
        /**
         * Used to indicate URL-encoded content.
         */
        const val CONTENT_TYPE_URL_ENCODED: Byte = 1
        /**
         * Used to indicate multi-part content.
         */
        const val CONTENT_TYPE_MULTIPART: Byte = 2
        /**
         * Used to indicate XML content.
         */
        const val CONTENT_TYPE_XML: Byte = 3
        /**
         * Used to indicate JSON content.
         */
        const val CONTENT_TYPE_JSON: Byte = 4
        /**
         * Used to indicate AMF content.
         */
        const val CONTENT_TYPE_AMF: Byte = 5
        /**
         * Used to indicate unknown content.
         */
        const val CONTENT_TYPE_UNKNOWN: Byte = -1
    }
}
