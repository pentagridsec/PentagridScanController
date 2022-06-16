package burp

/**
 * This interface is used for an
 * `IHttpRequestResponse` object that has had markers applied.
 * Extensions can create instances of this interface using
 * `IBurpExtenderCallbacks.applyMarkers()`, or provide their own
 * implementation. Markers are used in various situations, such as specifying
 * Intruder payload positions, Scanner insertion points, and highlights in
 * Scanner issues.
 */
interface IHttpRequestResponseWithMarkers : IHttpRequestResponse {
    /**
     * This method returns the details of the request markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * request message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * `null` if no request markers are defined.
     */
    val requestMarkers: List<IntArray>?

    /**
     * This method returns the details of the response markers.
     *
     * @return A list of index pairs representing the offsets of markers for the
     * response message. Each item in the list is an int[2] array containing the
     * start and end offsets for the marker. The method may return
     * `null` if no response markers are defined.
     */
    val responseMarkers: List<IntArray>?
}/*
 * @(#)IHttpRequestResponseWithMarkers.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
