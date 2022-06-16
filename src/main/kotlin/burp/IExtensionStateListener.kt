package burp

/*
 * @(#)IExtensionStateListener.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerExtensionStateListener()` to
 * register an extension state listener. The listener will be notified of
 * changes to the extension's state. **Note:** Any extensions that start
 * background threads or open system resources (such as files or database
 * connections) should register a listener and terminate threads / close
 * resources when the extension is unloaded.
 */
interface IExtensionStateListener {
    /**
     * This method is called when the extension is unloaded.
     */
    fun extensionUnloaded()
}
