package ui

import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class DocumentHandlerFunction(val function: (e: DocumentEvent?) -> Unit): DocumentListener {

    override fun insertUpdate(e: DocumentEvent?) {
        function(e)
    }

    override fun removeUpdate(e: DocumentEvent?) {
        function(e)
    }

    override fun changedUpdate(e: DocumentEvent?) {
        function(e)
    }

}