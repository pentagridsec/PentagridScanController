package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

import burp.IParameter

class CookieParameter(
    val parameter: IParameter
) : IParameter by parameter, ParameterAdvanced()
