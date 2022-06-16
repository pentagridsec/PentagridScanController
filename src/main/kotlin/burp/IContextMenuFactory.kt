package burp

/*
 * @(#)IContextMenuFactory.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

import javax.swing.JMenuItem

/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerContextMenuFactory()` to register
 * a factory for custom context menu items.
 */
interface IContextMenuFactory {
    /**
     * This method will be called by Burp when the user invokes a context menu
     * anywhere within Burp. The factory can then provide any custom context
     * menu items that should be displayed in the context menu, based on the
     * details of the menu invocation.
     *
     * @param invocation An object that implements the
     * `IMessageEditorTabFactory` interface, which the extension can
     * query to obtain details of the context menu invocation.
     * @return A list of custom menu items (which may include sub-menus,
     * checkbox menu items, etc.) that should be displayed. Extensions may
     * return
     * `null` from this method, to indicate that no menu items are
     * required.
     */
    fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem>
}
