package burp

/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerScannerInsertionPointProvider()`
 * to register a factory for custom Scanner insertion points.
 */
interface IScannerInsertionPointProvider {
    /**
     * When a request is actively scanned, the Scanner will invoke this method,
     * and the provider should provide a list of custom insertion points that
     * will be used in the scan. **Note:** these insertion points are used in
     * addition to those that are derived from Burp Scanner's configuration, and
     * those provided by any other Burp extensions.
     *
     * @param baseRequestResponse The base request that will be actively
     * scanned.
     * @return A list of
     * `IScannerInsertionPoint` objects that should be used in the
     * scanning, or
     * `null` if no custom insertion points are applicable for this
     * request.
     */
    fun getInsertionPoints(
            baseRequestResponse: IHttpRequestResponse): List<IScannerInsertionPoint>?
}/*
 * @(#)IScannerInsertionPointProvider.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
