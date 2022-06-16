package ui

import burp.IHttpRequestResponse
import burp.IHttpService
import burp.IMessageEditorController
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import javax.swing.JTable

class ScanStatusTable: JTable(), IMessageEditorController {
    val originalRequestViewer = BurpExtender.c.createMessageEditor(this, false)
    val originalResponseViewer = BurpExtender.c.createMessageEditor(this, false)
    val modifiedRequestViewer = BurpExtender.c.createMessageEditor(this, false)
    val modifiedResponseViewer = BurpExtender.c.createMessageEditor(this, false)
    private var currentlyDisplayedItem: IHttpRequestResponse? = null
    val tableModel: TableModel

    init{
        model = TableModel()
        tableModel = model as TableModel
    }

    override val httpService: IHttpService?
        get() = currentlyDisplayedItem?.httpService
    override val request: ByteArray?
        get() = currentlyDisplayedItem?.request
    override val response: ByteArray?
        get() = currentlyDisplayedItem?.response

    override fun changeSelection(row: Int, col: Int, toggle: Boolean, extend: Boolean){
        val logEntry = tableModel.element(convertRowIndexToModel(row))
        modifiedRequestViewer.setMessage(logEntry.modifiedMessageInfo.request, true)
        modifiedResponseViewer.setMessage(logEntry.modifiedMessageInfo.response ?: ByteArray(0), false)
        originalRequestViewer.setMessage(logEntry.originalMessageInfo.request, true)
        originalResponseViewer.setMessage(logEntry.originalMessageInfo.response!!, false)
        currentlyDisplayedItem = logEntry.modifiedMessageInfo
        super.changeSelection(row, col, toggle, extend)
    }
}