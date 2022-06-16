package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers

import burp.IRequestInfo

interface IRequestInfoAdvanced: IRequestInfo {
    val requestInfo: IRequestInfo
    val request: ByteArray
    val statusLine: String
    val relativeUrl: String
    val httpVersion: String
    val contentLengthHeader: String
    val contentLength: Int
    val contentTypeHeader: String?
    val headerBytes: ByteArray
    val bodyBytes: ByteArray
    val bodyString: String
    val hostnamePort: String
    val urlNameOfFileInPath: String
    val fileExtension: String
    val isMultipart: Boolean
    //These have to be lists because if they would be maps, every HTTP header could only exist once!
    val headersList: List<Pair<String, String>>
    val nonStandardHeaders: List<Pair<String, String>>

    fun createNewRelativeUrl(relativeUrl: String): ByteArray
    fun createNewHeaders(headersList: List<Pair<String, String>>): ByteArray

    //Multipart things
    val multipartBoundary: String
    val multiparts: List<String>
    val multipartNumberOfFiles: Int

    fun multipartHeadersFromFileIndex(fileIndex: Int = 0): List<String>
    fun multipartHeaders(index: Int): List<String>
    fun multipartHeaders(multipart: String): List<String>
    fun multipartBodyFromFileIndex(fileIndex: Int = 0): String
    fun multipartBody(index: Int): String
    fun multipartBody(multipart: String): String
    fun multipartContentTypeHeaderFromFileIndex(fileIndex: Int = 0): String
    fun multipartContentTypeHeader(index: Int): String
    fun multipartContentTypeFromFileIndex(fileIndex: Int = 0): String
    fun multipartContentType(index: Int): String
    fun multipartContentDispositionHeaderFromFileIndex(fileIndex: Int = 0): String
    fun multipartContentDispositionHeader(index: Int): String
    fun multipartContentDispositionHeader(multipart: String): String
    fun multipartContentDispositionFromFileIndex(fileIndex: Int = 0): String
    fun multipartContentDisposition(index: Int): String
    fun multipartContentDisposition(multipart: String): String
    fun multipartFilenameFromFileIndex(fileIndex: Int = 0): String
    fun multipartFilename(index: Int): String
    fun multipartFilename(multipart: String): String
    fun multipartParameternameFromFileIndex(fileIndex: Int = 0): String
    fun multipartParametername(index: Int): String
    fun multipartParametername(multipart: String): String
    fun multipartFileIndexToMultipartIndex(fileIndex: Int = 0): Int
    fun multipartMultipartIndexToFileIndex(index: Int): Int
    fun isFileMultipart(index: Int): Boolean
    fun isFileMultipart(multipart: String): Boolean
    fun createNewMultipart(index: Int, name: String?, filename: String?, content: String?): String
    fun createNewMultipart(multipart: String, name: String?, filename: String?, content: String?): String
    fun createMultipartBody(multiparts: List<String>): String


    companion object {

        const val newline = "\r\n"
        const val spaceStatusLineDelimiter = " "
        const val contentTypeMarker = "Content-Type: "
        const val contentLengthMarker = "Content-Length: "
        const val contentDispositionMarker = "Content-Disposition: "
        const val headerDelimiter = ": "
        const val multipartContentType = "multipart/form-data"
        const val boundaryMarker = "boundary="
        const val doubleDash = "--"
        const val charsetDelimiter = "; "
        const val contentDispositonValueFormData = "form-data; name=\""
        const val contentDispositonValueFilenameData = "\"; filename=\""
        const val contentDispositonValueDelimiter = "\""

        val knownHttpHeaders = listOf(
            "Accept-CH-Lifetime",
            "Accept-CH",
            "Accept-Charset",
            "Accept-Encoding",
            "Accept-Language",
            "Accept-Patch",
            "Accept-Post",
            "Accept-Ranges",
            "Accept",
            "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Origin",
            "Access-Control-Expose-Headers",
            "Access-Control-Max-Age",
            "Access-Control-Request-Headers",
            "Access-Control-Request-Method",
            "Age",
            "Allow",
            "Alt-Svc",
            "Authorization",
            "Cache-Control",
            "Clear-Site-Data",
            "Connection",
            "Content-Disposition",
            "Content-DPR",
            "Content-Encoding",
            "Content-Language",
            "Content-Length",
            "Content-Location",
            "Content-Range",
            "Content-Security-Policy-Report-Only",
            "Content-Security-Policy",
            "Content-Type",
            "Cookie",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Resource-Policy",
            "Date",
            "Device-Memory",
            "Digest",
            "DNT",
            "Downlink",
            "DPR",
            "Early-Data",
            "ECT",
            "ETag",
            "Expect-CT",
            "Expect",
            "Expires",
            "Feature-Policy",
            "Forwarded",
            "From",
            "Host",
            "If-Match",
            "If-Modified-Since",
            "If-None-Match",
            "If-Range",
            "If-Unmodified-Since",
            "Keep-Alive",
            "Large-Allocation",
            "Last-Modified",
            "Link",
            "Location",
            "NEL",
            "Origin",
            "Pragma",
            "Proxy-Authenticate",
            "Proxy-Authorization",
            "Public-Key-Pins-Report-Only",
            "Public-Key-Pins",
            "Range",
            "Referer",
            "Referrer-Policy",
            "Retry-After",
            "RTT",
            "Save-Data",
            "Sec-CH-UA-Arch",
            "Sec-CH-UA-Bitness",
            "Sec-CH-UA-Full-Version-List",
            "Sec-CH-UA-Full-Version",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Model",
            "Sec-CH-UA-Platform-Version",
            "Sec-CH-UA-Platform",
            "Sec-CH-UA",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-Fetch-User",
            "Sec-WebSocket-Accept",
            "Server-Timing",
            "Server",
            "Service-Worker-Navigation-Preload",
            "Set-Cookie",
            "SourceMap",
            "Strict-Transport-Security",
            "TE",
            "Timing-Allow-Origin",
            "Tk",
            "Trailer",
            "Transfer-Encoding",
            "Upgrade-Insecure-Requests",
            "Upgrade",
            "User-Agent",
            "Vary",
            "Via",
            "Viewport-Width",
            "Want-Digest",
            "Warning",
            "Width",
            "WWW-Authenticate",
            "X-Content-Type-Options",
            "X-DNS-Prefetch-Control",
            "X-Forwarded-For",
            "X-Forwarded-Host",
            "X-Forwarded-Proto",
            "X-Frame-Options",
            "X-XSS-Protection"
        )
        val knownHttpHeadersLower = knownHttpHeaders.map{it.lowercase()}

    }
}