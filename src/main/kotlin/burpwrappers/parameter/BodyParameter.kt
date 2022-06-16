package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

import burp.IParameter

//This should be called XFormUrlEncodedBodyParameter but let's not rename for the sake of staying with the same name
//as the Burp API

class BodyParameter(
    val parameter: IParameter
) : IParameter by parameter, ParameterAdvanced()