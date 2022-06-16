package burp

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender as BurpExtenderRealPackage

class BurpExtender : IBurpExtender {

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        BurpExtenderRealPackage().registerExtenderCallbacks(callbacks)
    }

}