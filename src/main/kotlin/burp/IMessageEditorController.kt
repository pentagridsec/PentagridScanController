package burp

/*
 * @(#)IMessageEditorController.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used by an
 * `IMessageEditor` to obtain details about the currently displayed
 * message. Extensions that create instances of Burp's HTTP message editor can
 * optionally provide an implementation of
 * `IMessageEditorController`, which the editor will invoke when it
 * requires further information about the current message (for example, to send
 * it to another Burp tool). Extensions that provide custom editor tabs via an
 * `IMessageEditorTabFactory` will receive a reference to an
 * `IMessageEditorController` object for each tab instance they
 * generate, which the tab can invoke if it requires further information about
 * the current message.
 */
interface IMessageEditorController {
    /**
     * This method is used to retrieve the HTTP service for the current message.
     *
     * @return The HTTP service for the current message.
     */
    val httpService: IHttpService?

    /**
     * This method is used to retrieve the HTTP request associated with the
     * current message (which may itself be a response).
     *
     * @return The HTTP request associated with the current message.
     */
    val request: ByteArray?

    /**
     * This method is used to retrieve the HTTP response associated with the
     * current message (which may itself be a request).
     *
     * @return The HTTP response associated with the current message.
     */
    val response: ByteArray?
}
