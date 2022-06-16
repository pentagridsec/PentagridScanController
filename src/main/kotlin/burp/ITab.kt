package burp

/*
 * @(#)ITab.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.Component

/**
 * This interface is used to provide Burp with details of a custom tab that will
 * be added to Burp's UI, using a method such as
 * `IBurpExtenderCallbacks.addSuiteTab()`.
 */
interface ITab {
    /**
     * Burp uses this method to obtain the caption that should appear on the
     * custom tab when it is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    val tabCaption: String

    /**
     * Burp uses this method to obtain the component that should be used as the
     * contents of the custom tab when it is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    val uiComponent: Component
}
