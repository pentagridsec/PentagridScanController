package ch.pentagrid.burpexts.pentagridscancontroller

import burp.*
import ui.DocumentHandlerFunction
import ui.HideRowFilter
import ui.ScanStatusTable
import ui.TableModel
import java.awt.*
import java.util.Timer
import javax.swing.*
import javax.swing.table.TableRowSorter
import kotlin.concurrent.schedule


class ScanUI(val burpExtender: BurpExtender): ITab {

    private val tabName = "Scan"

    var settings = Settings()
    private val optionsGbc = GridBagConstraints()
    private val optionsJPanel = JPanel()
    private val genericInset = Insets(2, 5, 2, 5)

    private val resetButton = JButton("Reset all settings")

    private val mainJtabedpane = JTabbedPane()

    val scanStatusTable = ScanStatusTable()

    private val about = """
        <html>
        <h2>$extensionName</h2>
        Author: Tobias "floyd" Ospelt, @floyd_ch, http://www.floyd.ch<br>
        Pentagrid AG, 5#, https://www.pentagrid.ch
        <h3>Improve Automated and Semi-Automated Active Scanning</h3>
        Active Scanning might often do things that don't make any sense, such as scanning GET requests to .js
        files or scanning non-repeatable request.
        This extension allows to filter and preprocess according to your needs. It tries to check if a request
        is repeatable or not. If a request is not repeatable, it tries to make them repeatable by injecting
        Hackvertor tags. The extension doesn't try to be perfect, but useful. It cuts corners and in some
        cases simply doesn't scan certain requests. However, the extension individually displays and explains
        all decisions, allowing you to change the settings if you don't like the behavior. It's a better 
        "Actively scan all in-scope traffic through Proxy".
        <h3>Features</h3>
        <ul>
        <li>Everything configurable (interesting/uninteresting, blacklisting requests, etc.)</li>
        </ul>
        <h3>Trophy case</h3>
        So far:
        <ul>
        <li>Unfortunately nothing so far, as I mainly do pentests with it. Did you find something?</li>
        </ul>
        <h3>Howto use this extension</h3>
        Usage is very simple:
        <ul>
        <li>Add the website you test to the scope</li>
        <li>Enable "Proxy requests" in the tab/section "Scan - Options - Requests to process"</li>
        <li>Browse the web application (proxy) by using the Burp builtin browser.</li>
        <li>Check back on the $tabName tab and see which request have been active scanned. Check those<br>
        that have a high "Interesting" rating but haven't been scanned ("Scanned" column set to false)</li>
        <li>See the Dashboard for Active Scan findings</li>
        <li>It's always good to sort by the reason column in the UI and check the different reasons.</li>
        </ul>
        <h3>Performance discussion</h3>
        Improves performance by not sending everything to active scan. 
        <h3>Ideas for future improvements</h3>
        <ul>
        <li>Let me know if you think of any improvements: tobias at pentagrid dot ch.</li>
        </ul>
        </html>
    """.trimIndent()

    init{
        createUi()
    }

    private fun fixScrolling(scrollpane: JScrollPane): JScrollPane {
        val systemLabel = JLabel()
        val metrics = systemLabel.getFontMetrics(systemLabel.font)
        val lineHeight = metrics.height
        val charWidth = metrics.maxAdvance
        val systemVBar = JScrollBar(JScrollBar.VERTICAL)
        val systemHBar = JScrollBar(JScrollBar.HORIZONTAL)
        val verticalIncrement = systemVBar.unitIncrement
        val horizontalIncrement = systemHBar.unitIncrement
        scrollpane.verticalScrollBar.unitIncrement = lineHeight * verticalIncrement
        scrollpane.horizontalScrollBar.unitIncrement = charWidth * horizontalIncrement
        return scrollpane
    }

    private fun addLabel(text: String): JLabel{
        val lbl = JLabel(text)
        optionsGbc.gridy += 1
        optionsGbc.gridx = 0
        optionsGbc.anchor = GridBagConstraints.EAST
        optionsJPanel.add(lbl, optionsGbc)
        optionsGbc.anchor = GridBagConstraints.CENTER
        return lbl
    }

    private fun addHeading(text: String){
        val lbl = JLabel(text)
        lbl.font = Font(lbl.font.fontName, Font.BOLD, lbl.font.size + 2)
        optionsGbc.gridy += 1
        optionsGbc.gridx = 0
        optionsGbc.gridwidth = 2
        optionsGbc.insets = Insets(15,5,8,5)
        optionsJPanel.add(lbl, optionsGbc)
        optionsGbc.gridwidth = 1
        optionsGbc.insets = genericInset
        BurpExtender.c.customizeUiComponent(lbl)
    }


    private fun addCheckbox(text: String, value: Boolean, default: Boolean, func: (Boolean) -> Unit){
        val lbl = addLabel(text)
        val box = JCheckBox("", value)
        box.addActionListener {
            func(box.isSelected)
            saveSettings()
        }
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                box.isSelected = default
            }
        }
        optionsGbc.gridx=1
        optionsJPanel.add(box, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(box)
    }

    private fun addString(text: String, value: String, default: String, func: (String) -> Unit){
        val lbl = addLabel(text)
        val field = JTextField(value, 15)
        field.document.addDocumentListener(
            DocumentHandlerFunction{
                try{
                    func(field.text)
                    saveSettings()
                    SwingUtilities.invokeLater {lbl.foreground = JLabel().foreground}
                }catch(e: Exception){
                    SwingUtilities.invokeLater {lbl.foreground = Color.RED}
                }
            }
        )
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                field.text = default
            }
        }
        optionsGbc.gridx = 1
        optionsJPanel.add(field, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(field)
    }

    private fun addInt(text: String, value: Int, default: Int, func: (Int) -> Unit){
        val lbl = addLabel(text)
        val field = JTextField(value.toString(), 10)
        field.document.addDocumentListener(
            DocumentHandlerFunction{
                try{
                    func(field.text.toInt())
                    saveSettings()
                    SwingUtilities.invokeLater {lbl.foreground = JLabel().foreground}
                }catch(e: Exception){
                        SwingUtilities.invokeLater {lbl.foreground = Color.RED}
                }
            }
        )
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                field.text = default.toString()
            }
        }
        optionsGbc.gridx = 1
        optionsJPanel.add(field, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(field)
    }

    private fun addLong(text: String, value: Long, default: Long, func: (Long) -> Unit){
        val lbl = addLabel(text)
        val field = JTextField(value.toString(), 10)
        field.document.addDocumentListener(
            DocumentHandlerFunction{
                try{
                    func(field.text.toLong())
                    saveSettings()
                    SwingUtilities.invokeLater {lbl.foreground = JLabel().foreground}
                }catch(e: Exception){
                    SwingUtilities.invokeLater {lbl.foreground = Color.RED}
                }
            }
        )
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                field.text = default.toString()
            }
        }
        optionsGbc.gridx = 1
        optionsJPanel.add(field, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(field)
    }

    private fun addListStrings(text: String, value: List<String>, default: List<String>, func: (List<String>) -> Unit){
        val lbl = addLabel("$text (one per line)")
        val rows = 5
        val columns = (value.maxOfOrNull { it.length } ?: 8).coerceAtMost(20).coerceAtLeast(8)
        val field = JTextArea(value.joinToString("\n"), rows, columns)
        field.document.addDocumentListener(
            DocumentHandlerFunction{
                try{
                    func(field.text.split("\n"))
                    saveSettings()
                    SwingUtilities.invokeLater {lbl.foreground = JLabel().foreground}
                }catch(e: Exception){
                    SwingUtilities.invokeLater {lbl.foreground = Color.RED}
                }
            }
        )
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                field.text = default.joinToString("\n")
            }
        }
        optionsGbc.gridx = 1
        val scroll = JScrollPane(field)
        scroll.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        optionsJPanel.add(scroll, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(field)
    }

    private fun addListShorts(text: String, value: List<Short>, default: List<Short>, func: (List<Short>) -> Unit){
        val lbl = addLabel("$text (one per line)")
        val rows = 5
        val columns = (value.maxOfOrNull { it.toString().length } ?: 8).coerceAtMost(20).coerceAtLeast(8)
        val field = JTextArea(value.joinToString("\n"), rows, columns)
        field.document.addDocumentListener(
            DocumentHandlerFunction{
                try {
                    func(field.text.split("\n").map { it.toShort() })
                    saveSettings()
                    SwingUtilities.invokeLater {lbl.foreground = JLabel().foreground}
                }catch(e: Exception){
                    SwingUtilities.invokeLater {lbl.foreground = Color.RED}
                }
            }
        )
        resetButton.addActionListener{
            SwingUtilities.invokeLater {
                field.text = default.joinToString("\n")
            }
        }
        optionsGbc.gridx = 1
        val scroll = JScrollPane(field)
        scroll.verticalScrollBarPolicy = JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        optionsJPanel.add(scroll, optionsGbc)
        BurpExtender.c.customizeUiComponent(lbl)
        BurpExtender.c.customizeUiComponent(field)
    }

    private fun addButton(text: String, func: () -> Unit) {
        val button = JButton(text)
        optionsGbc.gridy += 1
        button.addActionListener {
            func()
            saveSettings()
        }
        optionsGbc.gridx = 0
        optionsGbc.anchor = GridBagConstraints.EAST
        optionsJPanel.add(button, optionsGbc)
        optionsGbc.anchor = GridBagConstraints.CENTER
        BurpExtender.c.customizeUiComponent(button)
    }

    private fun createUi(){
        loadSettings()

        //Table
        scanStatusTable.rowSorter = TableRowSorter(scanStatusTable.model)
        (scanStatusTable.rowSorter as TableRowSorter<*>).rowFilter = HideRowFilter()

        //Context Menu
        val popupMenu = JPopupMenu()
        val hideItem = JMenuItem("Hide item(s)")
        hideItem.addActionListener {
            val indexes = scanStatusTable.selectedRows.map{scanStatusTable.convertRowIndexToModel(it)}
            scanStatusTable.tableModel.hideIndexes(indexes)
            sort()
        }
        popupMenu.add(hideItem)
        scanStatusTable.componentPopupMenu = popupMenu

        //About
        val aboutLbl = JTextPane()
        aboutLbl.contentType = "text/html"
        aboutLbl.isEditable = false
        aboutLbl.text = about
        val aboutPanel = fixScrolling(JScrollPane(aboutLbl))

        //Scan Status
        val scanStatusSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        //Request/Responses
        val tabs = JTabbedPane()
        tabs.addTab("Modified Request", scanStatusTable.modifiedRequestViewer.component)
        tabs.addTab("Modified Response", scanStatusTable.modifiedResponseViewer.component)
        tabs.addTab("Original Request", scanStatusTable.originalRequestViewer.component)
        tabs.addTab("Original Response", scanStatusTable.originalResponseViewer.component)

        val scrollPane = JScrollPane(scanStatusTable)

        scanStatusSplitPane.leftComponent = scrollPane
        scanStatusSplitPane.rightComponent = tabs

        // Here come the individual seettings

        val gridBagLayout = GridBagLayout()
        optionsJPanel.layout = gridBagLayout

        optionsGbc.gridy=-1
        optionsGbc.gridx=0
        optionsGbc.insets = genericInset

        val defaultSettings = Settings()

        var booleanSettingFunction: (Boolean) -> Unit
        var stringSettingFunction: (String) -> Unit
        var intSettingFunction: (Int) -> Unit
        var longSettingFunction: (Long) -> Unit
        var listStringSettingFunction: (List<String>) -> Unit
        var listShortSettingFunction: (List<Short>) -> Unit

        //Reset button is a little special, so we have to create it now, so we can already add actionListeners
        resetButton.addActionListener {
            settings = Settings()
            saveSettings()
        }

        addHeading("Only change settings marked with (!) if you really know what you do")

        addHeading("Requests to process (others won't show in UI)")

        booleanSettingFunction = { x: Boolean -> settings.scanProxy = x }
        addCheckbox("Proxy requests",
            settings.scanProxy, defaultSettings.scanProxy, booleanSettingFunction)

        /*
        // TODO BURP API limitation
        // Reactivate once https://twitter.com/floyd_ch/status/1519942261299159041?s=20&t=bCrlofC12TNxciP1hhIWcg is fixed
        booleanSettingFunction = { x: Boolean -> settings.scanSpider = x }
        addCheckbox("Process requests sent by Spider",
            settings.scanSpider, defaultSettings.scanSpider, booleanSettingFunction)
        */
        booleanSettingFunction = { x: Boolean -> settings.scanRepeater = x }
        addCheckbox("Repeater requests",
            settings.scanRepeater, defaultSettings.scanRepeater, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.onlyInScope = x }
        addCheckbox("In-scope only",
            settings.onlyInScope, defaultSettings.onlyInScope, booleanSettingFunction)

        addHeading("Scan configuration")

        longSettingFunction = { x: Long -> settings.delayScanForS = x}
        addLong("Delay scans in seconds (0 to disable)",
            settings.delayScanForS, defaultSettings.delayScanForS,
            longSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.doActiveScan = x }
        addCheckbox("Burp active scan",
            settings.doActiveScan, defaultSettings.doActiveScan, booleanSettingFunction)

        addHeading("Hard exclusions")

        booleanSettingFunction = { x: Boolean -> settings.onlyScanRepeatable = x }
        addCheckbox("Only scan repeatable requests (!)",
            settings.onlyScanRepeatable, defaultSettings.onlyScanRepeatable, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanUninterestingStatusCodes = x }
        addCheckbox("Never scan uninteresting HTTP status codes",
            settings.neverScanUninterestingStatusCodes, defaultSettings.neverScanUninterestingStatusCodes,
            booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanUninterestingMethods = x }
        addCheckbox("Never scan uninteresting HTTP methods",
            settings.neverScanUninterestingMethods, defaultSettings.neverScanUninterestingMethods,
            booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanGetToUninterestingFiles = x }
        addCheckbox(
            "Never scan GET requests to uninteresting URL file extensions",
            settings.neverScanGetToUninterestingFiles, defaultSettings.neverScanGetToUninterestingFiles,
            booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanUninterestingFiles = x }
        addCheckbox("Never scan requests to uninteresting URL file extensions",
            settings.neverScanUninterestingFiles, defaultSettings.neverScanUninterestingFiles, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanDuplicatesStatusUrlParameter = x }
        addCheckbox("Never scan duplicates (URL, status code, parameters, see Duplicates counter)",
            settings.neverScanDuplicatesStatusUrlParameter, defaultSettings.neverScanDuplicatesStatusUrlParameter, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.neverScanDuplicatesStatusUrl = x }
        addCheckbox("Never scan duplicates (URL, status code, see Duplicates counter)",
            settings.neverScanDuplicatesStatusUrl, defaultSettings.neverScanDuplicatesStatusUrl, booleanSettingFunction)

        stringSettingFunction = { x: String -> settings.neverScanUrlRegex = x }
        addString("Never scan request URLs matching this Regex",
            settings.neverScanUrlRegex, defaultSettings.neverScanUrlRegex, stringSettingFunction)

        stringSettingFunction = { x: String -> settings.neverScanRequestsRegex = x }
        addString("Never scan requests matching this Regex",
            settings.neverScanRequestsRegex, defaultSettings.neverScanRequestsRegex, stringSettingFunction)

        intSettingFunction = { x: Int -> settings.minimumScore = x}
        addInt("Only scan requests with a minimum interesting score of",
            settings.minimumScore, defaultSettings.minimumScore,
            intSettingFunction)

        addHeading("Repeatability")

        longSettingFunction = { x: Long -> settings.delayChecksForS = x}
        addLong("Delay repeatability checks in seconds (0 to disable)",
            settings.delayChecksForS, defaultSettings.delayChecksForS,
            longSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.useHeuristics = x }
        addCheckbox("Do heuristics",
            settings.useHeuristics, defaultSettings.useHeuristics,
            booleanSettingFunction)

        intSettingFunction = { x: Int -> settings.heuristicResponseLengthPercent = x }
        addInt("Maximum response length difference in %",
            settings.heuristicResponseLengthPercent, defaultSettings.heuristicResponseLengthPercent, intSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.heuristicWordsSuccess = x }
        addListStrings("Heuristic words: repetition success",
            settings.heuristicWordsSuccess, defaultSettings.heuristicWordsSuccess, listStringSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.heuristicWordsError = x }
        addListStrings("Heuristic words: repetition error",
            settings.heuristicWordsError, defaultSettings.heuristicWordsError, listStringSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.heuristicWordsFatal = x }
        addListStrings("Heuristic words: repetition fatal error",
            settings.heuristicWordsFatal, defaultSettings.heuristicWordsFatal, listStringSettingFunction)

        intSettingFunction = { x: Int -> settings.heuristicMaxFatal = x}
        addInt("Abort repeatability tests for current request if heuristic detects this many fatal errors",
            settings.heuristicMaxFatal, defaultSettings.heuristicMaxFatal,
            intSettingFunction)

        addHeading("Modifications for repeatability")

        intSettingFunction = { x: Int -> settings.maxRepeatabilityProbesPerRequest = x}
        addInt("Maximum requests until giving up",
            settings.maxRepeatabilityProbesPerRequest, defaultSettings.maxRepeatabilityProbesPerRequest,
            intSettingFunction)

        stringSettingFunction = { x: String -> settings.catchAllEmail = x }
        addString("Additional catch-all email domain used to detect if email is in a parameter (apart from Collaborator domain)",
            settings.catchAllEmail, defaultSettings.catchAllEmail, stringSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceUuid = x }
        addCheckbox("Change UUIDs in parameter values",
            settings.replaceUuid, defaultSettings.replaceUuid, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceEmail = x }
        addCheckbox("Change Emails in parameter values",
            settings.replaceEmail, defaultSettings.replaceEmail, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceNumeric = x }
        addCheckbox("Change Numerics [0-9]+ in parameter values",
            settings.replaceNumeric, defaultSettings.replaceNumeric, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceDouble = x }
        addCheckbox("Change Double [0-9]+\\.[0-9]+ in parameter values",
            settings.replaceDouble, defaultSettings.replaceDouble, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceUnixTimestamp = x }
        addCheckbox("Change unix epoch timestamps (now +/- 3 months, in seconds or milliseconds) in parameter values",
            settings.replaceUnixTimestamp, defaultSettings.replaceUnixTimestamp, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceAlphabetic = x }
        addCheckbox("Change Alphabetic [a-zA-Z] in parameter values",
            settings.replaceAlphabetic, defaultSettings.replaceAlphabetic, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceBirthdate = x }
        addCheckbox("Change Birthdate YYYY-MM-DD in parameter values",
            settings.replaceBirthdate, defaultSettings.replaceBirthdate, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceBoolean = x }
        addCheckbox("Change booleans (true, false, 0, 1, True, etc.) in parameter values",
            settings.replaceBoolean, defaultSettings.replaceBoolean, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.replaceCharset = x }
        addCheckbox("Change according to charset (e.g. 'foo_bar' might change to 'bffar_a') in parameter values",
            settings.replaceCharset, defaultSettings.replaceCharset, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamUrl = x }
        addCheckbox("Inject into URL query strings (Burp's PARAM_URL)",
            settings.injectParamUrl, defaultSettings.injectParamUrl, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamBody = x }
        addCheckbox("Inject into body (Burp's PARAM_BODY)",
            settings.injectParamBody, defaultSettings.injectParamBody, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamCookie = x }
        addCheckbox("Inject into cookies (Burp's PARAM_COOKIE)",
            settings.injectParamCookie, defaultSettings.injectParamCookie, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamNonStandardHeaders = x }
        addCheckbox("Inject into non-standard HTTP headers (this extension's PARAM_NON_STANDARD_HEADER)",
            settings.injectParamNonStandardHeaders, defaultSettings.injectParamNonStandardHeaders, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamXMLContent = x }
        addCheckbox("Inject into XML text nodes (this extension's PARAM_XML_CONTENT)",
            settings.injectParamXMLContent, defaultSettings.injectParamXMLContent, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamXMLAttr = x }
        addCheckbox("Inject into XML attributes (this extension's PARAM_XML_ATTR)",
            settings.injectParamXMLAttr, defaultSettings.injectParamXMLAttr, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamMultipartFilename = x }
        addCheckbox("Inject into multipart filename (this extension's PARAM_MULTIPART_FILENAME)",
            settings.injectParamMultipartFilename, defaultSettings.injectParamMultipartFilename, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamMultipartContent = x }
        addCheckbox("Inject into multipart content (this extension's PARAM_MULTIPART_CONTENT)",
            settings.injectParamMultipartContent, defaultSettings.injectParamMultipartContent, booleanSettingFunction)

        booleanSettingFunction = { x: Boolean -> settings.injectParamJson = x }
        addCheckbox("Inject into JSON values (this extension's PARAM_JSON)",
            settings.injectParamJson, defaultSettings.injectParamJson, booleanSettingFunction)

        addHeading("Other settings")

        booleanSettingFunction = { x: Boolean -> settings.debug = x }
        addCheckbox("Turn debug on (see extender output)",
            settings.debug, defaultSettings.debug, booleanSettingFunction)

        intSettingFunction = { x: Int -> settings.numberOfThreads = x }
        addInt("Use this many Threads to check repeatability/scan (requires extension reload) (!)",
            settings.numberOfThreads, defaultSettings.numberOfThreads, intSettingFunction)

        //Now add the reset button, which is a little a special case
        optionsGbc.gridy += 1
        optionsGbc.gridx = 0
        optionsGbc.anchor = GridBagConstraints.EAST
        optionsJPanel.add(resetButton, optionsGbc)
        optionsGbc.anchor = GridBagConstraints.CENTER
        BurpExtender.c.customizeUiComponent(resetButton)

        addButton("Unhide all log entries",
            fun() {
                scanStatusTable.tableModel.unhideAllLogEntries()
                sort()
            }
        )

        addButton("Delete all log entries",
            fun() {
                scanStatusTable.tableModel.deleteAllLogEntries()
                sort()
            }
        )

        addHeading("Detailed settings (un)interesting things")

        listStringSettingFunction = { x: List<String> -> settings.interestingUrlFileExtensions = x }
        addListStrings("Interesting URL file extensions",
            settings.interestingUrlFileExtensions, defaultSettings.interestingUrlFileExtensions, listStringSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.uninterestingUrlFileExtensions = x }
        addListStrings("Uninteresting URL file extensions",
            settings.uninterestingUrlFileExtensions, defaultSettings.uninterestingUrlFileExtensions, listStringSettingFunction)

        listShortSettingFunction = { x: List<Short> -> settings.interestingStatusCodes = x }
        addListShorts("Interesting status codes",
            settings.interestingStatusCodes, defaultSettings.interestingStatusCodes, listShortSettingFunction)

        listShortSettingFunction = { x: List<Short> -> settings.uninterestingStatusCodes = x }
        addListShorts("Uninteresting status codes",
            settings.uninterestingStatusCodes, defaultSettings.uninterestingStatusCodes, listShortSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.interestingMethods = x }
        addListStrings("Interesting HTTP methods",
            settings.interestingMethods, defaultSettings.interestingMethods, listStringSettingFunction)

        listStringSettingFunction = { x: List<String> -> settings.uninterestingMethods = x }
        addListStrings("Uninteresting HTTP methods",
            settings.uninterestingMethods, defaultSettings.uninterestingMethods, listStringSettingFunction)

        addHeading("Interesting score settings")

        intSettingFunction = { x: Int -> settings.pointsMultipart = x}
        addInt("Points for multipart/form-data requests",
            settings.pointsMultipart, defaultSettings.pointsMultipart,
            intSettingFunction)

        intSettingFunction = { x: Int -> settings.pointsInterestingMethod = x}
        addInt("Points for interesting HTTP request method",
            settings.pointsInterestingMethod, defaultSettings.pointsInterestingMethod,
            intSettingFunction)

        intSettingFunction = { x: Int -> settings.pointsInterestingFileExtension = x}
        addInt("Points for interesting URL file extension",
            settings.pointsInterestingFileExtension, defaultSettings.pointsInterestingFileExtension,
            intSettingFunction)

        intSettingFunction = { x: Int -> settings.pointsInterestingStatus = x}
        addInt("Points for interesting HTTP response status code",
            settings.pointsInterestingStatus, defaultSettings.pointsInterestingStatus,
            intSettingFunction)

        intSettingFunction = { x: Int -> settings.pointsPerParameter = x}
        addInt("Points per parameter",
            settings.pointsPerParameter, defaultSettings.pointsPerParameter,
            intSettingFunction)

        addHeading("Experimental features for repeatability definition settings")

        booleanSettingFunction = { x: Boolean -> settings.ignoreHttpStatusCodeWhenDecidingRepeatability = x }
        addCheckbox("Ignore HTTP Status Codes (!)",
            settings.ignoreHttpStatusCodeWhenDecidingRepeatability,
            defaultSettings.ignoreHttpStatusCodeWhenDecidingRepeatability, booleanSettingFunction)

        stringSettingFunction = { x: String -> settings.fixedResponse = x}
        addString("Fixed response content indicating 200 OK (!)",
            settings.fixedResponse, defaultSettings.fixedResponse, stringSettingFunction)


        val columnModel = scanStatusTable.columnModel
        val tableModel = scanStatusTable.tableModel
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.idColumn)).preferredWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.idColumn)).maxWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.duplicatesSeen)).preferredWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.duplicatesSeen)).maxWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.toolColumn)).preferredWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.toolColumn)).maxWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.method)).preferredWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.method)).maxWidth = 60
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.urlColumn)).preferredWidth = 300
        //columnModel.getColumn(tableModel.columns.indexOf(TableModel.urlColumn)).maxWidth = 300
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.statusCodeColumn)).preferredWidth = 105
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.statusCodeColumn)).maxWidth = 105
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.wasScannedColumn)).preferredWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.wasScannedColumn)).maxWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.interestingColumn)).preferredWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.interestingColumn)).maxWidth = 80
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.reasonColumn)).preferredWidth = 200
        //columnModel.getColumn(tableModel.columns.indexOf(TableModel.reasonColumn)).maxWidth = 200
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.repeatabilityColumn)).preferredWidth = 160
        columnModel.getColumn(tableModel.columns.indexOf(TableModel.repeatabilityColumn)).maxWidth = 160

        BurpExtender.c.customizeUiComponent(scanStatusSplitPane)
        BurpExtender.c.customizeUiComponent(scanStatusTable)
        BurpExtender.c.customizeUiComponent(scrollPane)
        BurpExtender.c.customizeUiComponent(tabs)

        mainJtabedpane.addTab("5# Scan Controller", null, scanStatusSplitPane, null)
        mainJtabedpane.addTab("Options", null, fixScrolling(JScrollPane(optionsJPanel)), null)
        mainJtabedpane.addTab("About & README", null, aboutPanel, null)

        loadLogEntries()

        // Important: Do this at the very end (otherwise we could run into troubles locking up entire threads)
        // add the custom tab to Burp's UI
        BurpExtender.c.addSuiteTab(this)

        //Check Hackvertor installed
        val scanUI = this
        Timer("DelayingHackvertorCheck", false).schedule(7000) {
            if(!BurpExtender.h.isHackvertorLoaded(scanUI)){
                val msg = "Hackvertor is not loaded (there is no Hackvertor tab in the UI!). " +
                        "Please install and load Hackvertor from BApp. Put Hackvertor " +
                        "in the list of loaded extensions *after* the '$extensionName' extension, otherwise " +
                        "extension '$extensionName' won't work! Last warning.\n"
                JOptionPane.showOptionDialog(
                    mainJtabedpane,
                    msg,
                    "Hackvertor not found",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.INFORMATION_MESSAGE,
                    null,
                    null,
                    null
                )
            }else{
                BurpExtender.println("Found Hackvertor tab, seems to be installed, good")
                if(!BurpExtender.h.isHackvertorUsable()){
                    val msg = "Hackvertor is not usable. Please put Hackvertor " +
                            "in the list of loaded extensions *after* the '$extensionName' extension, otherwise " +
                            "extension '$extensionName' won't work! Last warning.\n"
                    JOptionPane.showOptionDialog(
                        mainJtabedpane,
                        msg,
                        "Hackvertor not usable",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.INFORMATION_MESSAGE,
                        null,
                        null,
                        null
                    )
                }else{
                    BurpExtender.println("Hackvertor seems to be usable as well, good")
                }
            }
        }
    }

    fun sort(){
        SwingUtilities.invokeLater {
            (scanStatusTable.rowSorter as TableRowSorter<*>).sort()
        }
    }

    private fun loadSettings(){
        val s = PersistOverview.loadSettings()
        if(s == null) {
            val msg = "A new version of the $extensionName extension was installed, the settings are not " +
                    "compatible, so all settings have been reset (check the $tabName tab)."
            JOptionPane.showOptionDialog(
                mainJtabedpane,
                msg,
                "New $extensionName version",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.INFORMATION_MESSAGE,
                null,
                null,
                null
            )
        }else{
            settings = s
            BurpExtender.println("Old settings found from extension settings: $settings")
        }
    }

    private fun loadLogEntries() {
        //Load the already stored log entries from project settings
        val entries = PersistOverview.loadLogEntries()
        if(entries.isNotEmpty()){
            BurpExtender.println("Old table entries found from project settings: ${entries.size} entries")
        }
        scanStatusTable.tableModel.replaceAll(entries)
        sort()
    }

    fun save(){
        saveSettings()
        scanStatusTable.tableModel.saveLogEntries()
    }

    private fun saveSettings() {
        //println("Saving settings $settings")
        PersistOverview.saveSettings(settings)
    }

    override val tabCaption: String
        get() = tabName
    override val uiComponent: Component
        get() = mainJtabedpane

}

