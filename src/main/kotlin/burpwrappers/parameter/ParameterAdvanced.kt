package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

import burp.IParameter

abstract class ParameterAdvanced: IParameter{
    open fun uniqueIdentifier(): String {
        return "$type:$name:$value:$nameStart:$nameStart:$valueStart:$valueEnd"
    }

    companion object{
        fun getPseudoNames(params: List<ParameterAdvanced>): String{
            // Here's how we deal with the problem that a "parameter name" is not always defined
            // For UrlPathParameter the issue is ignored as the url is taken into consideration in duplicate checks...
            // Many other parameters have names
            // The only case left is JsonParameter
            // For example in a Json Array
            // [[1, "foo", "bar"], "baz"] no parameter has a name. Therefore that's the same with the below logic as:
            // ["k", true, 17, ["yes"]]
            // Even if we would include the Parameter type, this would still be the same:
            // ["k", "f", "b", ["yes"]] and
            // [["b", "foo", "bar"], "baz"] because all are of type PARAM_JSON_STRING
            // so the only option is to include the JsonParameter.path, that really identifies the location of a
            // parameter uniquely. Example for:
            // [["b", "foo", "bar"], "baz"]
            // is:
            // 0+0:0+1:0+2:1, whereas
            // ["k", "f", "b", ["yes"]] is:
            // 0:1:2:3+0
            // Something similar is true for XML:
            // <a b="c">d</a>
            // We make a distinction between the attributes and the text node inside the a tag
            return params.map { paramAdvanced ->
                if(paramAdvanced is JsonParameter && paramAdvanced.isPrimitiveType()){
                    paramAdvanced.path.joinToString("+") { locator -> locator.toString() }
                }else if(paramAdvanced is XmlParameter){
                    paramAdvanced.path.joinToString("+") { locator -> locator.toString() }
                }else if (paramAdvanced.name != null){
                    paramAdvanced.name
                }else{
                    ""
                }
            }.sortedBy { it
            }.joinToString(":")
        }
    }

}

