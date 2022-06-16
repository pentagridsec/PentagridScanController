package burp

/*
 * @(#)IMessageEditorTabFactory.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * Extensions can implement this interface and then call
 * `IBurpExtenderCallbacks.registerMessageEditorTabFactory()` to
 * register a factory for custom message editor tabs. This allows extensions to
 * provide custom rendering or editing of HTTP messages, within Burp's own HTTP
 * editor.
 */
interface IMessageEditorTabFactory {
    /**
     * Burp will call this method once for each HTTP message editor, and the
     * factory should provide a new instance of an
     * `IMessageEditorTab` object.
     *
     * @param controller An
     * `IMessageEditorController` object, which the new tab can query
     * to retrieve details about the currently displayed message. This may be
     * `null` for extension-invoked message editors where the
     * extension has not provided an editor controller.
     * @param editable Indicates whether the hosting editor is editable or
     * read-only.
     * @return A new
     * `IMessageEditorTab` object for use within the message editor.
     */
    fun createNewInstance(controller: IMessageEditorController?,
                          editable: Boolean): IMessageEditorTab
}
