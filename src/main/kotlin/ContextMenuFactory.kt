import burp.IContextMenuFactory
import burp.IContextMenuInvocation
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.BurpExtenderCallbacksAdvanced
import java.awt.event.ActionEvent
import javax.swing.AbstractAction
import javax.swing.JMenuItem


class ProcessMenuItemAction(private val invocation: IContextMenuInvocation): AbstractAction() {

    override fun actionPerformed(e: ActionEvent?) {
        val requestResponse = invocation.selectedMessages?.get(0)
        if(requestResponse?.response != null){
            BurpExtender.burpExtender.processHttpMessage(
                BurpExtenderCallbacksAdvanced.TOOL_CONTEXT, false,
                requestResponse)
        }
        else{
            BurpExtender.println("Request or Response were null")
        }
    }

}

/*
//TODO FEATURE
class MakeRepeatableMenuItemAction(private val invocation: IContextMenuInvocation): AbstractAction() {

    override fun actionPerformed(e: ActionEvent?) {
        val requestResponse = invocation.selectedMessages?.get(0)
        if(requestResponse?.response != null){
            val entry = LogEntry(
                SerializableHttpRequestResponse.fromHttpRequestResponse(requestResponse),
                SerializableHttpRequestResponse.fromHttpRequestResponse(requestResponse),
                BurpExtenderCallbacksAdvanced.TOOL_CONTEXT, mutableListOf()
            )
            val r = Repeater(entry)
            if (r.achieveRepeatable()) {

            }
        }
    }

}
*/

class ContextMenuFactory: IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem> {
        val action = ProcessMenuItemAction(invocation)
        val repeatable = JMenuItem(action)
        repeatable.text = "Process"



        return listOf(repeatable)
    }
}