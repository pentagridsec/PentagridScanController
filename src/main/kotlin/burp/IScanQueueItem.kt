package burp

/*
 * @(#)IScanQueueItem.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to retrieve details of items in the Burp Scanner
 * active scan queue. Extensions can obtain references to scan queue items by
 * calling
 * `IBurpExtenderCallbacks.doActiveScan()`.
 */
interface IScanQueueItem {
    /**
     * This method returns a description of the status of the scan queue item.
     *
     * @return A description of the status of the scan queue item.
     */
    val status: String

    /**
     * This method returns an indication of the percentage completed for the
     * scan queue item.
     *
     * @return An indication of the percentage completed for the scan queue
     * item.
     */
    val percentageComplete: Byte

    /**
     * This method returns the number of requests that have been made for the
     * scan queue item.
     *
     * @return The number of requests that have been made for the scan queue
     * item.
     */
    val numRequests: Int

    /**
     * This method returns the number of network errors that have occurred for
     * the scan queue item.
     *
     * @return The number of network errors that have occurred for the scan
     * queue item.
     */
    val numErrors: Int

    /**
     * This method returns the number of attack insertion points being used for
     * the scan queue item.
     *
     * @return The number of attack insertion points being used for the scan
     * queue item.
     */
    val numInsertionPoints: Int

    /**
     * This method returns details of the issues generated for the scan queue
     * item. **Note:** different items within the scan queue may contain
     * duplicated versions of the same issues - for example, if the same request
     * has been scanned multiple times. Duplicated issues are consolidated in
     * the main view of scan results. Extensions can register an
     * `IScannerListener` to get details only of unique, newly
     * discovered Scanner issues post-consolidation.
     *
     * @return Details of the issues generated for the scan queue item.
     */
    val issues: Array<IScanIssue>

    /**
     * This method allows the scan queue item to be canceled.
     */
    fun cancel()
}
