package burp

/*
 * @(#)IIntruderAttack.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details about an Intruder attack.
 */
interface IIntruderAttack {
    /**
     * This method is used to retrieve the HTTP service for the attack.
     *
     * @return The HTTP service for the attack.
     */
    val httpService: IHttpService

    /**
     * This method is used to retrieve the request template for the attack.
     *
     * @return The request template for the attack.
     */
    val requestTemplate: ByteArray

}
