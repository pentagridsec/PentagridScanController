package burp

/*
 * @(#)IMessageEditorTab.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.Component

/**
 * Extensions that register an
 * `IMessageEditorTabFactory` must return instances of this
 * interface, which Burp will use to create custom tabs within its HTTP message
 * editors.
 */
interface IMessageEditorTab {
    /**
     * This method returns the caption that should appear on the custom tab when
     * it is displayed. **Note:** Burp invokes this method once when the tab
     * is first generated, and the same caption will be used every time the tab
     * is displayed.
     *
     * @return The caption that should appear on the custom tab when it is
     * displayed.
     */
    val tabCaption: String

    /**
     * This method returns the component that should be used as the contents of
     * the custom tab when it is displayed. **Note:** Burp invokes this
     * method once when the tab is first generated, and the same component will
     * be used every time the tab is displayed.
     *
     * @return The component that should be used as the contents of the custom
     * tab when it is displayed.
     */
    val uiComponent: Component

    /**
     * This method returns the currently displayed message.
     *
     * @return The currently displayed message.
     */
    val message: ByteArray?

    /**
     * This method is used to determine whether the currently displayed message
     * has been modified by the user. The hosting editor will always call
     * `getMessage()` before calling this method, so any pending
     * edits should be completed within
     * `getMessage()`.
     *
     * @return The method should return
     * `true` if the user has modified the current message since it
     * was first displayed.
     */
    val isModified: Boolean

    /**
     * This method is used to retrieve the data that is currently selected by
     * the user.
     *
     * @return The data that is currently selected by the user. This may be
     * `null` if no selection is currently made.
     */
    val selectedData: ByteArray?

    /**
     * The hosting editor will invoke this method before it displays a new HTTP
     * message, so that the custom tab can indicate whether it should be enabled
     * for that message.
     *
     * @param content The message that is about to be displayed, or a zero-length
     * array if the existing message is to be cleared.
     * @param isRequest Indicates whether the message is a request or a
     * response.
     * @return The method should return
     * `true` if the custom tab is able to handle the specified
     * message, and so will be displayed within the editor. Otherwise, the tab
     * will be hidden while this message is displayed.
     */
    fun isEnabled(content: ByteArray, isRequest: Boolean): Boolean

    /**
     * The hosting editor will invoke this method to display a new message or to
     * clear the existing message. This method will only be called with a new
     * message if the tab has already returned
     * `true` to a call to
     * `isEnabled()` with the same message details.
     *
     * @param content The message that is to be displayed, or
     * `null` if the tab should clear its contents and disable any
     * editable controls.
     * @param isRequest Indicates whether the message is a request or a
     * response.
     */
    fun setMessage(content: ByteArray?, isRequest: Boolean)
}
