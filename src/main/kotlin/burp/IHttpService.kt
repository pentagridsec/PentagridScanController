package burp

/*
 * @(#)IHttpService.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to provide details about an HTTP service, to which
 * HTTP requests can be sent.
 */
interface IHttpService {
    /**
     * This method returns the hostname or IP address for the service.
     *
     * @return The hostname or IP address for the service.
     */
    val host: String

    /**
     * This method returns the port number for the service.
     *
     * @return The port number for the service.
     */
    val port: Int

    /**
     * This method returns the protocol for the service.
     *
     * @return The protocol for the service. Expected values are "http" or
     * "https".
     */
    val protocol: String
}
