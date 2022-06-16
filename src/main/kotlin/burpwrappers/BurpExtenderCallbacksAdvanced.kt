package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers

import burp.IBurpExtenderCallbacks


class BurpExtenderCallbacksAdvanced(val callbacks: IBurpExtenderCallbacks) : IBurpExtenderCallbacks by callbacks {
    companion object {
        /**
         * Flag used to identify the Burp context menu
         */
        const val TOOL_CONTEXT = 0x00001337
    }

    override fun getToolName(toolFlag: Int): String {
        if(toolFlag == TOOL_CONTEXT){
            return "User"
        }
        return callbacks.getToolName(toolFlag)
    }
}