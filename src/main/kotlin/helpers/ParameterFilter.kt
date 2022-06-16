package ch.pentagrid.burpexts.pentagridscancontroller.helpers

import burp.IParameter
import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*


class ParameterFilter {
    companion object {
        fun filter(parameters: List<ParameterAdvanced>): List<ParameterAdvanced> {
            return parameters.filter {
                !(
                    (it.type == IParameter.PARAM_URL && !BurpExtender.ui.settings.injectParamUrl) ||
                    (it.type == IParameter.PARAM_BODY && !BurpExtender.ui.settings.injectParamBody) ||
                    (it.type == IParameter.PARAM_COOKIE && !BurpExtender.ui.settings.injectParamCookie) ||
                    (it.type == PARAM_NON_STANDARD_HEADER_TYPE && !BurpExtender.ui.settings.injectParamNonStandardHeaders) ||
                    (it.type == PARAM_XML_CONTENT && !BurpExtender.ui.settings.injectParamXMLContent) ||
                    (it.type == PARAM_XML_ATTR && !BurpExtender.ui.settings.injectParamXMLAttr) ||
                    (it.type == PARAM_MULTIPART_FILENAME && !BurpExtender.ui.settings.injectParamMultipartFilename) ||
                    (it.type == PARAM_MULTIPART_CONTENT && !BurpExtender.ui.settings.injectParamMultipartContent) ||
                    (it.type in PARAM_JSON_NULL..PARAM_JSON_DICT && !BurpExtender.ui.settings.injectParamJson)
                )
            }
        }
    }
}