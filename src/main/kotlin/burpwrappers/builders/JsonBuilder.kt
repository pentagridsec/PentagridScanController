package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*
import com.beust.klaxon.JsonArray
import com.beust.klaxon.JsonObject
import com.beust.klaxon.KlaxonException
import com.beust.klaxon.Parser
import java.math.BigInteger


class JsonBuilder(private val jsonContent: String){
    fun getParameters(onlyFirst: Boolean = false, noComplex: Boolean = true): List<JsonParameter> {
        return if(jsonContent.toDoubleOrNull() != null){
            val i = JsonInt()
            i.init(null, jsonContent, mutableListOf())
            listOf(i)
        }else {
            try {
                val first: Any = Parser.default().parse(java.lang.StringBuilder(jsonContent))
                val all: MutableList<JsonParameter> = mutableListOf()
                recursiveExtract(all, null, first, mutableListOf(), onlyFirst, noComplex)
                all
            }catch(e: KlaxonException){
                if(BurpExtender.ui.settings.debug) {
                    BurpExtender.println("KlaxonException: Seems this is not valid JSON! ${e.toString().replace("\n", " ").replace("\r", " ")}")
                }
                emptyList()
            }
        }
    }

    fun setParameter(j: JsonParameter): String {
        if(jsonContent.toDoubleOrNull() != null && j.path.isEmpty()){
            return j.value
        }else {
            val parameters = getParameters(onlyFirst = true, noComplex = false)
            val futureBody = parameters[0]
            val firstElement: Any? = futureBody.klaxonStructure
            var referencedElement: Any? = firstElement
            for(k in 0 until (j.path.size - 1)){
                val e = j.path[k]
                if(e is ArrayIndex){
                    referencedElement = (referencedElement as JsonArray<*>)[e.index]
                }else if(e is DictKey){
                    referencedElement = (referencedElement as JsonObject)[e.key]
                }
            }
            val e = j.path.last()
            var correctValue: Any? = j.value
            if(e is ArrayIndex || e is DictKey){
                try {
                    when (j) {
                        is JsonNull -> {
                            correctValue = null
                        }
                        is JsonInt -> {
                            correctValue = j.value.toInt()
                        }
                        is JsonLong -> {
                            correctValue = j.value.toLong()
                        }
                        is JsonBigInteger -> {
                            correctValue = j.value.toBigInteger()
                        }
                        is JsonString -> {
                            correctValue = j.value
                        }
                        is JsonDouble -> {
                            correctValue = j.value.toDouble()
                        }
                        is JsonBoolean -> {
                            correctValue = j.value.toBoolean()
                        }
                        is JsonDict -> {
                            correctValue = j.klaxonStructure as JsonObject
                        }
                        is JsonList -> {
                            @Suppress("UNCHECKED_CAST")
                            correctValue = j.klaxonStructure as JsonArray<Any?>
                        }
                    }
                }catch(exception: NumberFormatException){
                    correctValue = j.value
                }catch(exception: java.lang.ClassCastException){
                    BurpExtender.println("Class cast exception! $exception")
                }
            }
            if(e is ArrayIndex){
                try {
                    @Suppress("UNCHECKED_CAST")
                    (referencedElement as JsonArray<Any?>).value[e.index] = correctValue
                }catch(exception: java.lang.ClassCastException){
                    BurpExtender.println("Class cast exception! $exception")
                }
            }else if(e is DictKey){
                (referencedElement as JsonObject).map.remove(e.key)
                referencedElement.map[j.name!!] = correctValue
            }
            return when (firstElement) {
                is JsonObject -> {
                    firstElement.toJsonString()
                }
                is JsonArray<*> -> {
                    firstElement.toJsonString()
                }
                else -> {
                    futureBody.value
                }
            }

        }
    }

    private fun recursiveExtract(
        all: MutableList<JsonParameter>,
        keyName: String?,
        currentValue: Any?,
        path: MutableList<JsonLocator>,
        onlyFirst: Boolean = false,
        noComplex: Boolean = true
    ){
        var parameter: JsonParameter? = null
        when (currentValue) {
            null -> {
                parameter = JsonNull()
            }
            is Int -> {
                parameter = JsonInt()
            }
            is Long -> {
                parameter = JsonLong()
            }
            is BigInteger -> {
                parameter = JsonBigInteger()
            }
            is String -> {
                parameter = JsonString()
            }
            is Double -> {
                parameter = JsonDouble()
            }
            is Boolean -> {
                parameter = JsonBoolean()
            }
        }
        if(parameter != null){
            parameter.init(keyName, currentValue, path)
            all.add(parameter)
        }else{
            if(currentValue is JsonObject){
                if(!noComplex){
                    parameter = JsonDict()
                    parameter.init(keyName, currentValue, path)
                    all.add(parameter)
                }
                for(key in currentValue.map){
                    val newPath = path.toMutableList()
                    newPath.add(DictKey(key.key))
                    if(!onlyFirst)
                        recursiveExtract(all, key.key, key.value, newPath)
                }
            }else if(currentValue is JsonArray<*>) {
                if(!noComplex){
                    parameter = JsonList()
                    parameter.init(keyName, currentValue, path)
                    all.add(parameter)
                }
                for(index in currentValue.indices){
                    val value = currentValue[index]
                    val newPath = path.toMutableList()
                    newPath.add(ArrayIndex(index))
                    if(!onlyFirst)
                        recursiveExtract(all, null, value, newPath)
                }
            }else{
                println("Unknown type $currentValue")
                return
            }
        }
    }
}