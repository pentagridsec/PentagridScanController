package burp

/*
 * @(#)IScopeChangeListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerScopeChangeListener()` to register
 * a scope change listener. The listener will be notified whenever a change
 * occurs to Burp's suite-wide target scope.
 */
interface IScopeChangeListener {
    /**
     * This method is invoked whenever a change occurs to Burp's suite-wide
     * target scope.
     */
    fun scopeChanged()
}
