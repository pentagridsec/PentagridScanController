package ui

import burp.IResponseInfo
import burpwrappers.RequestInfoAdvanced
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry
import ch.pentagrid.burpexts.pentagridscancontroller.PersistOverview
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.ParameterAdvanced
import ch.pentagrid.burpexts.pentagridscancontroller.helpers.ParameterFilter
import java.net.URL
import java.util.*
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel
import kotlin.collections.ArrayList

class TableModel: AbstractTableModel() {

    companion object {
        const val idColumn = "ID"
        const val duplicatesSeen = "Duplicates"
        const val method = "Method"
        const val urlColumn = "URL"
        const val toolColumn = "Tool"
        const val statusCodeColumn = "Status Code"
        const val wasScannedColumn = "Scanned"
        const val interestingColumn = "Interesting"
        const val reasonColumn = "Repeatability reasoning or why it was not scanned"
        const val repeatabilityColumn = "#repeatability requests"
    }

    private val log = Collections.synchronizedList(ArrayList<LogEntry>())

    val columns = arrayOf(
        idColumn,
        duplicatesSeen,
        toolColumn,
        method,
        urlColumn,
        statusCodeColumn,
        wasScannedColumn,
        interestingColumn,
        reasonColumn,
        repeatabilityColumn
    )

    override fun getValueAt(index: Int, columnIndex: Int): Any {
        val logEntry = log[index]
        return when (columnIndex) {
            0 -> index
            1 -> logEntry.duplicatesSeen
            2 -> BurpExtender.c.getToolName(logEntry.toolFlag)
            3 -> logEntry.originalRequestInfo.method
            4 -> logEntry.originalRequestInfo.url.toString()
            5 -> logEntry.originalResponseInfo.statusCode
            6 -> logEntry.wasScanned
            7 -> logEntry.interestingScore
            8 -> logEntry.reasons.joinToString(", ")
            9 -> logEntry.repeatabilityFixNumberOfSentRequests
            else -> ""
        }
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when(columnIndex) {
            0 -> Integer::class.java //idColumn
            1 -> Integer::class.java //duplicatesSeen
            2 -> String::class.java //toolColumn
            3 -> String::class.java //method
            4 -> String::class.java //urlColumn
            5 -> Short::class.java //statusCodeColumn
            6 -> Boolean::class.java //wasScannedColumn
            7 -> Integer::class.java //interestingColumn
            8 -> String::class.java //reasonColumn
            9 -> Integer::class.java //repeatabilityColumn
            else -> String::class.java
        }
    }

    override fun getRowCount(): Int {
        return log.size
    }

    override fun getColumnCount(): Int {
        return columns.size
    }

    override fun getColumnName(columnIndex: Int): String {
        return columns[columnIndex]
    }

    fun replaceAll(candidates: List<LogEntry>) {
        //TODO FEATURE: wrap saveBuffersToTempFiles
        //val persisted = BurpExtender.c.saveBuffersToTempFiles(candidate.originalMessageInfo)
        //candidate.originalMessageInfo = persisted
        var first: Int = -1
        var last = 0
        synchronized (log) {
            log.clear()
            for(candidate in candidates) {
                last = log.size
                if(first < 0)
                    first = last
                candidate.id = last
                log.add(candidate)
            }
        }
        //this function is called by the GUI thread, so this would lead to a thread-lock if it is at the same time logLock.locked
        if(first != -1) {
            SwingUtilities.invokeLater {
                fireTableRowsInserted(first, last)
            }
        }
        saveLogEntries()
    }

    fun add(candidate: LogEntry) {
        //TODO FEATURE: wrap saveBuffersToTempFiles
        //val persisted = BurpExtender.c.saveBuffersToTempFiles(candidate.originalMessageInfo)
        //candidate.originalMessageInfo = persisted
        synchronized (log) {
            val row = log.size
            candidate.id = row
            log.add(candidate)
            SwingUtilities.invokeLater {
                //Unfortunately I couldn't make this work. I've got way too many ArrayIndexOutOfBounds
                //when the table was sorted differently or rows were hidden
                //fireTableRowsInserted(row, row)
                //so let's use the more expensive
                fireTableDataChanged()
            }
        }
        saveLogEntries()
    }

    fun hideIndexes(index: List<Int>){
        synchronized(log) {
            for (i in index) {
                log[i].hidden = true
            }
        }
        saveLogEntries()
    }

    fun isDuplicate(url: URL, requestInfo: RequestInfoAdvanced, responseInfo: IResponseInfo): Boolean{
        val urlForDuplicateCheck = url.host.toString() + url.path.toString() + ":" + responseInfo.statusCode
        val paramForDuplicateCheck = urlForDuplicateCheck + ":" +
                ParameterAdvanced.getPseudoNames(ParameterFilter.filter(requestInfo.parameters))
        synchronized (log) {
            for(existingLogEntry in log){
                val existingUrl = existingLogEntry.originalRequestInfo.url!!
                val existingUrlForDuplicateCheck = existingUrl.host.toString() + existingUrl.path.toString() + ":" +
                        responseInfo.statusCode
                if(BurpExtender.ui.settings.neverScanDuplicatesStatusUrl){
                    if(existingUrlForDuplicateCheck == urlForDuplicateCheck) {
                        if(BurpExtender.ui.settings.debug){
                            BurpExtender.println("Found duplicate $existingUrlForDuplicateCheck")
                        }
                        existingLogEntry.duplicatesSeen += 1
                        if(!existingLogEntry.hidden)
                            announceDataChangeCell(existingLogEntry.id, duplicatesSeen)
                        return true
                    }
                } else if(BurpExtender.ui.settings.neverScanDuplicatesStatusUrlParameter){
                    val existingParamForDuplicateCheck = existingUrlForDuplicateCheck + ":" +
                            ParameterAdvanced.getPseudoNames(ParameterFilter.filter(existingLogEntry.originalRequestInfo.parameters))
                    if(existingParamForDuplicateCheck == paramForDuplicateCheck) {
                        if(BurpExtender.ui.settings.debug){
                            BurpExtender.println("Found duplicate $existingParamForDuplicateCheck")
                        }
                        existingLogEntry.duplicatesSeen += 1
                        if(!existingLogEntry.hidden)
                            announceDataChangeCell(existingLogEntry.id, duplicatesSeen)
                        return true
                    }
                }
            }
        }
        return false
    }

    fun isHidden(index: Int): Boolean{
        return log[index].hidden
    }

    fun element(index: Int): LogEntry{
        return log[index]
    }

    fun announceDataChangeCell(index: Int, columnName: String) {
        SwingUtilities.invokeLater {
            fireTableCellUpdated(index, columns.indexOf(columnName))
        }
    }

    fun announceDataChangeRow(index: Int) {
        SwingUtilities.invokeLater {
            fireTableRowsUpdated(index, index)
        }
    }

    fun unhideAllLogEntries() {
        synchronized(log){
            for(i in log.indices) {
                if(log[i].hidden) {
                    log[i].hidden = false
                }
            }
        }
        saveLogEntries()
    }

    fun deleteAllLogEntries() {
        log.clear()
        saveLogEntries()
    }

    fun saveLogEntries() {
        synchronized(log){
            PersistOverview.saveLogEntries(log)
        }
    }

}