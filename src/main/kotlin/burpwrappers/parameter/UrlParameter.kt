package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

import burp.IParameter

class UrlParameter(
    val parameter: IParameter
) : IParameter by parameter, ParameterAdvanced()
