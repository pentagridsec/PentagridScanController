package ch.pentagrid.burpexts.pentagridscancontroller

import java.io.Serializable

data class Settings(
    var onlyInScope: Boolean = true,

    var scanProxy: Boolean = false,
    var scanSpider: Boolean = false,
    var scanRepeater: Boolean = false,

    var onlyScanRepeatable: Boolean = true,
    var neverScanUrlRegex: String = "/login",
    var neverScanRequestsRegex: String = "",
    var neverScanUninterestingMethods: Boolean = true,
    var neverScanUninterestingStatusCodes: Boolean = true,
    var neverScanUninterestingFiles: Boolean = false,
    var neverScanGetToUninterestingFiles: Boolean = true,
    var neverScanDuplicatesStatusUrlParameter: Boolean = true,
    var neverScanDuplicatesStatusUrl: Boolean = false,
    var minimumScore: Int = 0,
    // Neutral file extensions: json, text, html, htm, xhtml, xml or no file extension and everything else
    var interestingUrlFileExtensions: List<String> = listOf(
        // Mainly "dynamic" things
        "jsp", "jspx", "jspa", "jst", "jsf",
        "asp", "aspx",
        "exe", "dll",
        "py",
        "pl", "cgi", "fcgi",
        "php", "phtml", "phtm", "php2", "php3", "php4", "php5", "php6", "php7",
        "shtml", "stml", "stm",
        "psp",
        "ognc",
        "cfm"
    ),
    var uninterestingUrlFileExtensions: List<String> = listOf(
        // Mainly "static" things are excluded
        "js", "js.map", "css", "css.map",
        "swf", "zip", "gz", "7zip", "war", "jar", "doc", "docx", "xls", "xlsx", "pdf", "exe", "dll",
        "png", "jpeg", "jpg", "bmp", "tif", "tiff", "gif", "webp", "svg", "ico",
        "m3u", "mp4", "m4a", "ogg", "aac", "flac", "mp3", "wav", "avi", "mov", "mpeg", "wmv", "webm",
        "woff", "woff2", "ttf"
    ),
    //TODO: Implement Content-Types
    var interestingContentTypes: List<String> = listOf(
        // Mainly "dynamic" things
        "application/json",
    ),
    var uninterestingContentTypes: List<String> = listOf(
        // Mainly "static" things are excluded
        "text/javascript"
    ),
    var interestingStatusCodes: List<Short> = listOf(200),
    var uninterestingStatusCodes: List<Short> = listOf(101, 304, 400, 401, 403, 404, 429, 502, 504, 505),
    var interestingMethods: List<String> = listOf("POST", "PUT", "PATCH", "DELETE"),
    var uninterestingMethods: List<String> = listOf("OPTIONS"),
    var pointsMultipart: Int = 50,
    var pointsInterestingMethod: Int = 100,
    var pointsInterestingFileExtension: Int = 100,
    var pointsInterestingStatus: Int = 100,
    var pointsPerParameter: Int = 1,

    var debug: Boolean = false,
    var fixedResponse: String = "",
    // Things that are
    var replaceUuid: Boolean = true,
    var replaceEmail: Boolean = true,
    var replaceNumeric: Boolean = true,
    var replaceDouble: Boolean = true,
    var replaceUnixTimestamp: Boolean = true,
    var replaceAlphabetic: Boolean = true,
    var replaceBirthdate: Boolean = true,
    var replaceBoolean: Boolean = true,
    var replaceCharset: Boolean = true,
    var injectParamUrl: Boolean = true,
    var injectParamBody: Boolean = true,
    var injectParamCookie: Boolean = false,
    var injectParamNonStandardHeaders: Boolean = true,
    var injectParamXMLContent: Boolean = true,
    var injectParamXMLAttr: Boolean = true,
    var injectParamMultipartFilename: Boolean = true,
    var injectParamMultipartContent: Boolean = true,
    var injectParamJson: Boolean = true,

    var maxRepeatabilityProbesPerRequest: Int = 300,

    var doActiveScan: Boolean = true,
    var catchAllEmail: String = "",

    var delayChecksForS: Long = 5,
    var delayScanForS: Long = 30,
    var ignoreHttpStatusCodeWhenDecidingRepeatability: Boolean = false,
    var useHeuristics: Boolean = true,
    var heuristicResponseLengthPercent: Int = 15,
    var heuristicWordsSuccess: List<String> = listOf(
        "\"status\":200", "\"status\":\"200\"", "'status':200", "'status':'200'", //JSON
        "status=200", //generic
        "status:200", // HTTP header
    ),
    var heuristicWordsError: List<String> = listOf(
        //English
        "exception", "error", "fail", "fault", "null",
        "issue", "problem",
        "expect", "reject", "deny", "denied", "discard", "allow", "admit", "permit", "accept", //e.g. not admitted, expected numeric, not allowed, disallowed,
        "valid", "correct", //not valid, not correct, invalid, incorrect
        "taken", "unique", "duplicate", "identic", "already",
        //German
        "fehler", "falsch",
        "erwartet", "erlaubt", "akzeptiert",
        "duplikat", "besetzt", "verwendet",
    ),
    var heuristicWordsFatal: List<String> = listOf(
        //English
        "expired", "invalidated",
        //German
        "abgelaufen",
    ),
    var heuristicMaxFatal: Int = 10,
    val defaultEncoding: String = "UTF-8",
    var numberOfThreads: Int = 5

    ): Serializable{

    override fun toString(): String {
        return "onlyInScope: $onlyInScope, scanProxy: $scanProxy, scanSpider: $scanSpider, " +
                "scanRepeater: $scanRepeater, onlyScanRepeatable: $onlyScanRepeatable, " +
                "neverScanUninterestingMethods: $neverScanUninterestingMethods, " +
                "neverScanUrlRegex: $neverScanUrlRegex, " +
                "neverScanRequestsRegex: $neverScanRequestsRegex, " +
                "neverScanUninterestingStatusCodes: $neverScanUninterestingStatusCodes" +
                "neverScanUninterestingFiles: $neverScanUninterestingFiles, " +
                "neverScanGetToUninterestingFiles: $neverScanGetToUninterestingFiles" +
                "uninterestingUrlFileExtensions: $uninterestingUrlFileExtensions, " +
                "interestingUrlFileExtensions: $interestingUrlFileExtensions, " +
                "neverScanDuplicatesStatusUrlParameter: $neverScanDuplicatesStatusUrlParameter, " +
                "neverScanDuplicatesStatusUrl: $neverScanDuplicatesStatusUrl, " +
                "minimumScore: $minimumScore, " +
                "uninterestingStatusCodes: $uninterestingStatusCodes, " +
                "interestingStatusCodes: $interestingStatusCodes, " +
                "interestingMethods: $interestingMethods, " +
                "debug: $debug, " +
                "fixedResponse: $fixedResponse, " +
                "replaceUuid: $replaceUuid, replaceEmail: $replaceEmail, catchAllEmail: $catchAllEmail, " +
                "replaceNumeric: $replaceNumeric, " +
                "replaceDouble: $replaceDouble, " +
                "replaceUnixTimestamp: $replaceDouble, " +
                "replaceAlphabetic: $replaceAlphabetic, " +
                "replaceBirthdate: $replaceBirthdate, " +
                "replaceBoolean: $replaceBoolean, " +
                "replaceCharset: $replaceCharset, " +
                "injectParamUrl: $injectParamUrl, " +
                "injectParamBody: $injectParamBody, " +
                "injectParamCookie: $injectParamCookie, " +
                "injectParamNonStandardHeaders: $injectParamNonStandardHeaders, " +
                "injectParamXMLContent: $injectParamXMLContent, " +
                "injectParamXMLAttr: $injectParamXMLAttr, " +
                "injectParamMultipartFilename: $injectParamMultipartFilename, " +
                "injectParamMultipartContent: $injectParamMultipartContent, " +
                "injectParamJson: $injectParamJson, " +
                "maxRepeatabilityProbesPerRequest: $maxRepeatabilityProbesPerRequest, " +
                "doActiveScan: $doActiveScan, " +
                "delayChecksForMs: $delayChecksForS, " +
                "delayScanForMs: $delayScanForS, " +
                "ignoreHttpStatusCodeWhenDecidingRepeatability: $ignoreHttpStatusCodeWhenDecidingRepeatability," +
                "useHeuristics: $useHeuristics," +
                "heuristicResponseLengthPercent: $heuristicResponseLengthPercent, " +
                "heuristicWordsSuccess: $heuristicWordsSuccess, " +
                "heuristicWordsError: $heuristicWordsError, " +
                "heuristicWordsFatal: $heuristicWordsFatal, " +
                "heuristicMaxFatal: $heuristicMaxFatal, " +
                "defaultEncoding: $defaultEncoding, " +
                "numberOfThreads: $numberOfThreads"
    }

}