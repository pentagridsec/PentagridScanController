package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

const val PARAM_JSON_NULL: Byte = 0xa0.toByte()
const val PARAM_JSON_INT: Byte = 0xa1.toByte()
const val PARAM_JSON_LONG: Byte = 0xa2.toByte()
const val PARAM_JSON_BIG_INTEGER: Byte = 0xa3.toByte()
const val PARAM_JSON_STRING: Byte = 0xa4.toByte()
const val PARAM_JSON_DOUBLE: Byte = 0xa5.toByte()
const val PARAM_JSON_BOOLEAN: Byte = 0xa6.toByte()
const val PARAM_JSON_LIST: Byte = 0xa7.toByte()
const val PARAM_JSON_DICT: Byte = 0xa8.toByte()


open class JsonLocator{
    override fun toString(): String {
        if(this is ArrayIndex){
            return index.toString()
        }
        else if(this is DictKey){
            return key
        }
        return ""
    }
}
class ArrayIndex(val index: Int): JsonLocator()
class DictKey(val key: String): JsonLocator()

abstract class JsonParameter: ParameterAdvanced(){
    abstract override val type: Byte
    override var name: String? = null
    override var value: String = ""
    override val nameStart: Int = 0
    override val nameEnd: Int = 0
    override val valueStart: Int = 0
    override val valueEnd: Int = 0
    /*
    How path works:
    Let's assume we have:
    [
        {
        "foo":["a, "b", "c"]
        }
    ]
    Then path to the value "b" is:
    listOf(ArrayIndex(0), DictKey("foo"), ArrayIndex(1))
    basically saying take index 0 (the dictonary in the list), then take value of "foo", then it's index 1 in that list
     */
    var klaxonStructure: Any? = null
    var path: MutableList<JsonLocator> = mutableListOf()
    fun init(nameInit: String?, valueInit: Any?, pathInit: MutableList<JsonLocator>){
        this.name = nameInit
        this.klaxonStructure = valueInit
        this.value = valueInit.toString()
        this.path = pathInit
    }
    override fun uniqueIdentifier(): String {
        val pathString = path.map{ if(it is ArrayIndex){it.index.toString()}else{if(it is DictKey){it.key}else{""}} }
        return super.uniqueIdentifier() + ":${pathString.joinToString(";")}"
    }

    fun isPrimitiveType(): Boolean{
        //Primitive types are all except list and dictionary
        return this.type <= PARAM_JSON_NULL && this.type <= PARAM_JSON_BOOLEAN
    }
}

class JsonNull: JsonParameter() {
    override val type: Byte = PARAM_JSON_NULL
}

class JsonInt: JsonParameter() {
    override val type: Byte = PARAM_JSON_INT
}

class JsonLong: JsonParameter() {
    override val type: Byte = PARAM_JSON_LONG
}

class JsonBigInteger: JsonParameter() {
    override val type: Byte = PARAM_JSON_BIG_INTEGER
}

class JsonString: JsonParameter() {
    override val type: Byte = PARAM_JSON_STRING
}

class JsonDouble: JsonParameter() {
    override val type: Byte = PARAM_JSON_DOUBLE
}

class JsonBoolean: JsonParameter() {
    override val type: Byte = PARAM_JSON_BOOLEAN
}

class JsonList: JsonParameter() {
    override val type: Byte = PARAM_JSON_LIST
}

class JsonDict: JsonParameter() {
    override val type: Byte = PARAM_JSON_DICT
}

