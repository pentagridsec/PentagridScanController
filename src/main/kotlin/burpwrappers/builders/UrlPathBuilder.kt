package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders

import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.UrlPathParameter

const val randomReplacerForEndHackvertor = "PLACEHOLDERplaceHACKVERTORholderPLACEHOLDER"

class UrlPathBuilder(private val relativeUrl: String){
    var thingsAfterFilename: String = ""


    fun urlParts(): List<String>{
        var cleaned = relativeUrl
        //Ignore Hackvertor end tag slashes in URL parameters
        cleaned = splitAndDivide(cleaned, "?")
        cleaned = splitAndDivide(cleaned, "#")
        cleaned = splitAndDivide(cleaned, ";")
        cleaned = cleaned.replace("</@", randomReplacerForEndHackvertor + "1")
        cleaned = cleaned.replace("/>", randomReplacerForEndHackvertor + "2")
        val splitted = cleaned.split("/").drop(1)
        return splitted.map{ it.replace(randomReplacerForEndHackvertor + "2", "/>").replace(randomReplacerForEndHackvertor + "1", "</@")}
    }

    private fun splitAndDivide(input: String, delimiter: String): String{
        val split = input.split(delimiter, limit = 1)
        if(split.size > 1){
            thingsAfterFilename = delimiter + split[1] + thingsAfterFilename
        }
        return split[0]
    }

    fun getParameters(): Collection<UrlPathParameter> {
        val paths = urlParts()
        val params = mutableListOf<UrlPathParameter>()
        for(index in paths.indices){
            params.add(UrlPathParameter(paths[index], index))
        }
        return params
    }

    fun setParameter(u: UrlPathParameter): String {
        val paths = urlParts().toMutableList()
        paths[u.index] = u.value
        return "/" + paths.joinToString("/") + thingsAfterFilename
    }

}