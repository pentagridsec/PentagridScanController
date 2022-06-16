package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

import org.w3c.dom.Node

const val PARAM_XML_CONTENT: Byte = 0xb4.toByte()
const val PARAM_XML_ATTR: Byte = 0xb5.toByte()

open class XmlLocator{
    override fun toString(): String {
        if(this is XmlElementIndex){
            return "E$index"
        } else if(this is XmlAttributeIndex){
            return "A$index"
        }
        return ""
    }
}
class XmlElementIndex(val index: Int): XmlLocator()
class XmlAttributeIndex(val index: Int): XmlLocator()

abstract class XmlParameter: ParameterAdvanced(){
    abstract override val type: Byte
    override var name: String? = null
    override var value: String = ""
    override val nameStart: Int = 0
    override val nameEnd: Int = 0
    override val valueStart: Int = 0
    override val valueEnd: Int = 0

    lateinit var xmlNode: Node
    var path: MutableList<XmlLocator> = mutableListOf()

    fun init(node: Node, nameInit: String?, valueInit: String, pathInit: MutableList<XmlLocator>){
        this.xmlNode = node
        this.name = nameInit
        this.value = valueInit
        this.path = pathInit
    }
    override fun uniqueIdentifier(): String {
        val pathString = path.map{ it.toString() }
        return super.uniqueIdentifier() + ":${pathString.joinToString(";")}"
    }
}

class XmlContentParameter: XmlParameter(){
    override val type: Byte = PARAM_XML_CONTENT
}

class XmlAttrParameter : XmlParameter(){
    override val type: Byte = PARAM_XML_ATTR
}
