package burp

/*
 * @(#)IHttpRequestResponsePersisted.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used for an
 * `IHttpRequestResponse` object whose request and response messages
 * have been saved to temporary files using
 * `IBurpExtenderCallbacks.saveBuffersToTempFiles()`.
 */
interface IHttpRequestResponsePersisted : IHttpRequestResponse {

    @Deprecated("This method is deprecated and no longer performs any action.")
    fun deleteTempFiles()
}
