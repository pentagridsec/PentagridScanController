package ch.pentagrid.burpexts.pentagridscancontroller

import burpwrappers.RequestInfoAdvanced
import burpwrappers.SerializableHttpRequestResponse
import java.net.URL


data class Candidate(
    val toolFlag: Int, val messageInfo: SerializableHttpRequestResponse,
    val url: URL, val requestInfo: RequestInfoAdvanced, val start: Long
)