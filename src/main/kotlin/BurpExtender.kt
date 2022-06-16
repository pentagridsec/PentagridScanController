package ch.pentagrid.burpexts.pentagridscancontroller

import ContextMenuFactory
import burp.*
import burpwrappers.ExtensionHelpersAdvanced
import burpwrappers.SerializableHttpRequestResponse
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.BurpExtenderCallbacksAdvanced
import ui.TableModel
import java.io.PrintWriter
import java.util.*
import java.util.concurrent.*
import kotlin.concurrent.schedule

const val extensionName = "5# Scan Controller"

class BurpExtender : IBurpExtender, IExtensionStateListener, IHttpListener {

    companion object {
        // These act more or less like globals in the entire code
        lateinit var c: BurpExtenderCallbacksAdvanced
        lateinit var h: ExtensionHelpersAdvanced
        lateinit var ui: ScanUI
        lateinit var burpExtender: BurpExtender
        lateinit var stdout: PrintWriter
        lateinit var stderr: PrintWriter
        var threads: MutableList<ThreadWorker> = mutableListOf()
        var unload = false
        //BlockingQueue is cool, if you take() and its empty it will block until some other thread has put() something in it
        var queuedCandidates: BlockingQueue<Candidate> = LinkedBlockingQueue()

        fun println(s: String){
            stdout.println(s)
        }

    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        c = BurpExtenderCallbacksAdvanced(callbacks)
        h = ExtensionHelpersAdvanced(c.helpers)

        c.setExtensionName(extensionName)

        stdout = PrintWriter(c.stdout, true)
        stderr = PrintWriter(c.stderr, true)

        println("Loading $extensionName")

        burpExtender = this
        ui = ScanUI(this)

        //Run the threads
        for (i in 0 until ui.settings.numberOfThreads) {
            val thread = ThreadWorker(this)
            thread.name = "$extensionName message processor $i"
            threads.add(thread)
            thread.start()
        }

        // Get notified when extension is unloaded
        c.registerExtensionStateListener(this)

        c.registerHttpListener(this)

        c.registerContextMenuFactory(ContextMenuFactory())

        println("$extensionName loaded")
    }

    override fun extensionUnloaded(){
        unload = true
        println("Saving the settings")
        ui.save()
        println("Finishing all threads")
        for(thread in threads){
            thread.interrupt()
        }
        println("Finished all threads and ready for shutdown")
    }

    override fun processHttpMessage(toolFlag: Int, messageIsRequest: Boolean, messageInfo: IHttpRequestResponse) {
        if (!messageIsRequest) {
            val start = System.currentTimeMillis()
            if(ui.settings.scanProxy && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY){
                //Fine
            }else if(ui.settings.scanSpider && toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER){
                //Fine
            }else if(ui.settings.scanRepeater && toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER){
                //Fine (debugging)
            }else if(toolFlag == BurpExtenderCallbacksAdvanced.TOOL_CONTEXT){
                //Fine (manual from the context menu)
            }else{
                /*
                if(ui.settings.debug){
                    println("We don't scan ${c.getToolName(toolFlag)} requests: $url")
                }
                 */
                return
            }
            val requestInfo = h.analyzeRequest(messageInfo)
            val url = requestInfo.url
            if(url == null){
                println("Error: iRequestInfo.url is null (e.g. if you broke the HTTP request line structure)")
                return
            }
            if(ui.settings.onlyInScope && !c.isInScope(url)){
                /*
                if(ui.settings.debug){
                    println("Not in scope: $url")
                }
                 */
                if(toolFlag != BurpExtenderCallbacksAdvanced.TOOL_CONTEXT)
                    return
            }

            if(messageInfo.response == null){
                /*
                if(ui.settings.debug){
                    println("Response is null")
                }
                 */
                return
            }
            //We are not interested in keeping Burp longer than necessary to send this response to the
            //browser, therefore create a queue that does all the work in the background with a ThreadPool
            //But remember, we also don't want to create too many queue entries, that's why the filtering is done
            //before a request is queued
            if(!unload) {
                queuedCandidates.put(Candidate(toolFlag,
                    SerializableHttpRequestResponse.fromHttpRequestResponse(messageInfo), url, requestInfo, start))
            }
        }
    }

    //Gets called by Thread Worker Pool
    fun processHttpMessageOwnThread(candidate: Candidate) {
        val responseInfo = h.analyzeResponse(candidate.messageInfo.response!!)

        // checkDuplicates will just increase the "Duplicates" column
        // except when sending manually via context menu or duplicate checks disabled
        if(candidate.toolFlag != BurpExtenderCallbacksAdvanced.TOOL_CONTEXT &&
            (ui.settings.neverScanDuplicatesStatusUrlParameter || ui.settings.neverScanDuplicatesStatusUrl) &&
            ui.scanStatusTable.tableModel.isDuplicate(candidate.url, candidate.requestInfo, responseInfo))
            return

        // Every entry that makes it until here gets its own row in the table
        val entry = LogEntry(SerializableHttpRequestResponse.fromHttpRequestResponse(candidate.messageInfo),
            SerializableHttpRequestResponse.fromHttpRequestResponse(candidate.messageInfo),
            candidate.toolFlag, mutableSetOf()
        )
        ui.scanStatusTable.tableModel.add(entry)

        //The "interesting" analysis
        if(candidate.requestInfo.isMultipart){
            entry.interestingScore += ui.settings.pointsMultipart
        }
        if(ui.settings.interestingMethods.contains(candidate.requestInfo.method)){
            entry.interestingScore += ui.settings.pointsInterestingMethod
        }
        if(candidate.requestInfo.fileExtension.isNotEmpty() &&
            ui.settings.interestingUrlFileExtensions.contains(candidate.requestInfo.fileExtension)) {
            entry.interestingScore += ui.settings.pointsInterestingFileExtension
        }
        if(ui.settings.interestingStatusCodes.contains(responseInfo.statusCode)) {
            entry.interestingScore += ui.settings.pointsInterestingStatus
        }
        val parameters = candidate.requestInfo.parameters
        // How many parameters we are interested in
        entry.interestingScore += parameters.size * ui.settings.pointsPerParameter
        ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.interestingColumn)

        // TODO FEATURE: Interesting parameter values?
        //entry.addInterestingScore(parameters.count{it.value.contains(Regex("/"))})

        if(ui.settings.minimumScore > entry.interestingScore){
            entry.reasons += "-Interesting score ${entry.interestingScore} lower than minimum ${ui.settings.minimumScore}"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            return
        }

        if(ui.settings.neverScanUrlRegex.isNotEmpty() &&
            Regex(ui.settings.neverScanUrlRegex).containsMatchIn(candidate.url.toString())){
            entry.reasons += "-URL matches the 'don't scan regex' '${ui.settings.neverScanUrlRegex}'"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            return
        }

        if(ui.settings.neverScanRequestsRegex.isNotEmpty() &&
            Regex(ui.settings.neverScanRequestsRegex).containsMatchIn(candidate.messageInfo.requestString)){
            entry.reasons += "-Request matches the 'don't scan regex' '${ui.settings.neverScanRequestsRegex}'"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            return
        }
        //TODO: Create "never scan responses matching regex"

        if(ui.settings.neverScanUninterestingMethods && ui.settings.uninterestingMethods.contains(candidate.requestInfo.method)){
            entry.reasons += "-Never scan ${candidate.requestInfo.method} requests"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            return
        }

        if((ui.settings.neverScanGetToUninterestingFiles && candidate.requestInfo.method == "GET") ||
            ui.settings.neverScanUninterestingFiles)  {
            val fileExtension = candidate.requestInfo.fileExtension
            if (fileExtension.isNotEmpty() &&
                ui.settings.uninterestingUrlFileExtensions.contains(fileExtension)) {
                entry.reasons += "-GET to uninteresting file extension $fileExtension"
                ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                return
            }
        }

        if(ui.settings.neverScanUninterestingStatusCodes && ui.settings.uninterestingStatusCodes.contains(responseInfo.statusCode)) {
            entry.reasons += "-Never scan uninteresting status code ${responseInfo.statusCode}"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            return
        }
        val remaining = ui.settings.delayChecksForS * 1000 - (System.currentTimeMillis() - candidate.start)
        if(remaining > 0) {
            entry.reasons += "+Repeat in ${ui.settings.delayChecksForS}s"
            ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
            Timer("DelayingChecks", false).schedule(ui.settings.delayChecksForS * 1000) {
                checkRepeatability(entry)
            }
        }else{
            checkRepeatability(entry)
        }
        //Not needed, we announced every single cell anyway
        //ui.scanStatusTable.tableModel.announceDataChangeRow(entry.id)
    }



    private fun checkRepeatability(entry: LogEntry){
        val r = Repeater(entry)
        if (!ui.settings.onlyScanRepeatable || r.achieveRepeatable()) {
            if(ui.settings.delayScanForS > 0) {
                entry.reasons += "+Scan in ${ui.settings.delayScanForS}s"
                ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                Timer("DelayingScan", false).schedule(ui.settings.delayScanForS * 1000) {
                    scan(entry)
                }
            }else{
                scan(entry)
            }
        }
    }

    fun scan(entry: LogEntry){
        if (!ui.settings.onlyScanRepeatable) {
            val r = RepeatableDetector(RepeaterSender(entry), entry)
            if(!r.isLookingRepeatable()) {
                entry.reasons += "-Repeatability broke before scanning!"
                entry.reasons.addAll(r.reasonsForFail)
                ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.reasonColumn)
                return
            }
        }

        entry.wasScanned = true
        ui.scanStatusTable.tableModel.announceDataChangeCell(entry.id, TableModel.wasScannedColumn)

        if(ui.settings.doActiveScan) {
            c.doActiveScan(entry.modifiedMessageInfo.httpService.host, entry.modifiedMessageInfo.httpService.port,
                    entry.modifiedMessageInfo.httpService.protocol == "https", entry.modifiedMessageInfo.request)
        }
        //TODO FEATURE: Now that we know it is repeatable, we can do fancy checks, because we can just send
        //the entry.modifiedMessage again and if the response is not indicating repeatability we know it was a bad
        //request

    }

}