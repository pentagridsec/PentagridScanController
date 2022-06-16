package burp

/*
 * @(#)IBurpExtender.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * All extensions must implement this interface.
 *
 * Implementations must be called BurpExtender, in the package burp, must be
 * declared public, and must provide a default (public, no-argument)
 * constructor.
 */
interface IBurpExtender {
    /**
     * This method is invoked when the extension is loaded. It registers an
     * instance of the
     * `IBurpExtenderCallbacks` interface, providing methods that may
     * be invoked by the extension to perform various actions.
     *
     * @param callbacks An
     * `IBurpExtenderCallbacks` object.
     */
    fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks)
}
