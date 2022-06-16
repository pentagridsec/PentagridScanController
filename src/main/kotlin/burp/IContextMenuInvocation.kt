package burp

/*
 * @(#)IContextMenuInvocation.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.awt.event.InputEvent

/**
 * This interface is used when Burp calls into an extension-provided
 * `IContextMenuFactory` with details of a context menu invocation.
 * The custom context menu factory can query this interface to obtain details of
 * the invocation event, in order to determine what menu items should be
 * displayed.
 */
interface IContextMenuInvocation {

    /**
     * This method can be used to retrieve the native Java input event that was
     * the trigger for the context menu invocation.
     *
     * @return The `InputEvent` that was the trigger for the context
     * menu invocation.
     */
    val inputEvent: InputEvent

    /**
     * This method can be used to retrieve the Burp tool within which the
     * context menu was invoked.
     *
     * @return A flag indicating the Burp tool within which the context menu was
     * invoked. Burp tool flags are defined in the
     * `IBurpExtenderCallbacks` interface.
     */
    val toolFlag: Int

    /**
     * This method can be used to retrieve the context within which the menu was
     * invoked.
     *
     * @return An index indicating the context within which the menu was
     * invoked. The indices used are defined within this interface.
     */
    val invocationContext: Byte

    /**
     * This method can be used to retrieve the bounds of the user's selection
     * into the current message, if applicable.
     *
     * @return An int[2] array containing the start and end offsets of the
     * user's selection in the current message. If the user has not made any
     * selection in the current message, both offsets indicate the position of
     * the caret within the editor. If the menu is not being invoked from a
     * message editor, the method returns `null`.
     */
    val selectionBounds: IntArray

    /**
     * This method can be used to retrieve details of the HTTP requests /
     * responses that were shown or selected by the user when the context menu
     * was invoked.
     *
     * **Note:** For performance reasons, the objects returned from this
     * method are tied to the originating context of the messages within the
     * Burp UI. For example, if a context menu is invoked on the Proxy intercept
     * panel, then the
     * `IHttpRequestResponse` returned by this method will reflect
     * the current contents of the interception panel, and this will change when
     * the current message has been forwarded or dropped. If your extension
     * needs to store details of the message for which the context menu has been
     * invoked, then you should query those details from the
     * `IHttpRequestResponse` at the time of invocation, or you
     * should use
     * `IBurpExtenderCallbacks.saveBuffersToTempFiles()` to create a
     * persistent read-only copy of the
     * `IHttpRequestResponse`.
     *
     * @return An array of `IHttpRequestResponse` objects
     * representing the items that were shown or selected by the user when the
     * context menu was invoked. This method returns `null` if no
     * messages are applicable to the invocation.
     */
    val selectedMessages: Array<IHttpRequestResponse>?

    /**
     * This method can be used to retrieve details of the Scanner issues that
     * were selected by the user when the context menu was invoked.
     *
     * @return An array of `IScanIssue` objects representing the
     * issues that were selected by the user when the context menu was invoked.
     * This method returns `null` if no Scanner issues are applicable
     * to the invocation.
     */
    val selectedIssues: Array<IScanIssue>?

    companion object {
        /**
         * Used to indicate that the context menu is being invoked in a request
         * editor.
         */
        const val CONTEXT_MESSAGE_EDITOR_REQUEST: Byte = 0
        /**
         * Used to indicate that the context menu is being invoked in a response
         * editor.
         */
        const val CONTEXT_MESSAGE_EDITOR_RESPONSE: Byte = 1
        /**
         * Used to indicate that the context menu is being invoked in a non-editable
         * request viewer.
         */
        const val CONTEXT_MESSAGE_VIEWER_REQUEST: Byte = 2
        /**
         * Used to indicate that the context menu is being invoked in a non-editable
         * response viewer.
         */
        const val CONTEXT_MESSAGE_VIEWER_RESPONSE: Byte = 3
        /**
         * Used to indicate that the context menu is being invoked in the Target
         * site map tree.
         */
        const val CONTEXT_TARGET_SITE_MAP_TREE: Byte = 4
        /**
         * Used to indicate that the context menu is being invoked in the Target
         * site map table.
         */
        const val CONTEXT_TARGET_SITE_MAP_TABLE: Byte = 5
        /**
         * Used to indicate that the context menu is being invoked in the Proxy
         * history.
         */
        const val CONTEXT_PROXY_HISTORY: Byte = 6
        /**
         * Used to indicate that the context menu is being invoked in the Scanner
         * results.
         */
        const val CONTEXT_SCANNER_RESULTS: Byte = 7
        /**
         * Used to indicate that the context menu is being invoked in the Intruder
         * payload positions editor.
         */
        const val CONTEXT_INTRUDER_PAYLOAD_POSITIONS: Byte = 8
        /**
         * Used to indicate that the context menu is being invoked in an Intruder
         * attack results.
         */
        const val CONTEXT_INTRUDER_ATTACK_RESULTS: Byte = 9
        /**
         * Used to indicate that the context menu is being invoked in a search
         * results window.
         */
        const val CONTEXT_SEARCH_RESULTS: Byte = 10
    }
}
