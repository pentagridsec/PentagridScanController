package burp

/**
 * This interface is used to retrieve key details about an HTTP response.
 * Extensions can obtain an
 * `IResponseInfo` object for a given response by calling
 * `IExtensionHelpers.analyzeResponse()`.
 */
interface IResponseInfo {
    /**
     * This method is used to obtain the HTTP headers contained in the response.
     *
     * @return The HTTP headers contained in the response.
     */
    val headers: List<String>

    /**
     * This method is used to obtain the offset within the response where the
     * message body begins.
     *
     * @return The offset within the response where the message body begins.
     */
    val bodyOffset: Int

    /**
     * This method is used to obtain the HTTP status code contained in the
     * response.
     *
     * @return The HTTP status code contained in the response.
     */
    val statusCode: Short

    /**
     * This method is used to obtain details of the HTTP cookies set in the
     * response.
     *
     * @return A list of `ICookie` objects representing the cookies
     * set in the response, if any.
     */
    val cookies: List<ICookie>

    /**
     * This method is used to obtain the MIME type of the response, as stated in
     * the HTTP headers.
     *
     * @return A textual label for the stated MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    val statedMimeType: String

    /**
     * This method is used to obtain the MIME type of the response, as inferred
     * from the contents of the HTTP message body.
     *
     * @return A textual label for the inferred MIME type, or an empty String if
     * this is not known or recognized. The possible labels are the same as
     * those used in the main Burp UI.
     */
    val inferredMimeType: String
}/*
 * @(#)IResponseInfo.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
