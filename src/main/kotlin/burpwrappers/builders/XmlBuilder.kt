package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.requestbuilders

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter.*
import org.w3c.dom.Document
import org.w3c.dom.Node
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.StringReader
import java.io.StringWriter
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult


class XmlBuilder(private val xmlContent: String){

    private fun getDocument(): Document? {
        //Make sure we never load external entities first...
        val docBuilderFactory = DocumentBuilderFactory.newInstance()
        docBuilderFactory.isValidating = false
        docBuilderFactory.isNamespaceAware = false
        docBuilderFactory.setFeature("http://xml.org/sax/features/namespaces", false)
        docBuilderFactory.setFeature("http://xml.org/sax/features/validation", false)
        docBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-dtd-grammar", false)
        docBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        val docBuilder = docBuilderFactory.newDocumentBuilder()
        docBuilder.setEntityResolver { _, _ ->
            InputSource(StringReader(""))
        }
        //Now really parse the XML document content
        val doc: Document
        try {
            doc = docBuilder.parse(ByteArrayInputStream(xmlContent.toByteArray()))
        }catch (e: SAXException){
            BurpExtender.println("SAXException when parsing XML: $e")
            return null
        }catch (e: IOException){
            BurpExtender.println("IOException when parsing XML: $e")
            return null
        }
        return doc
    }

    fun getParameters(): List<XmlParameter> {
        val doc = getDocument() ?: return emptyList()
        val all: MutableList<XmlParameter> = mutableListOf()
        recursiveExtract(all, doc.documentElement, mutableListOf())
        return all
    }

    fun setParameter(j: XmlParameter): String {
        val doc = getDocument() ?: return ""
        var referencedElement = doc.documentElement as Node
        for (k in 0 until (j.path.size - 1)) {
            val e = j.path[k]
            if (e is XmlElementIndex) {
                referencedElement = referencedElement.childNodes.item(e.index)
            }else{
                break
            }
        }
        if (j.path.size > 0 && j.path.last() is XmlAttributeIndex) {
            // We inject into Attribute
            val attr = referencedElement.attributes.item((j.path.last() as XmlAttributeIndex).index)
            if (attr.nodeName != j.name) {
                //TODO FEATURE
                BurpExtender.println("Changing Attribute Node name was not yet implemented. You wanted to change" +
                        " ${attr.nodeName} to ${j.name}")
            }
            attr.nodeValue = j.value
        } else {
            //Take also the last one of the path
            referencedElement = referencedElement.childNodes.item((j.path.last() as XmlElementIndex).index)
            // We have a leave node
            if (referencedElement.nodeName != j.name) {
                //TODO FEATURE
                BurpExtender.println("Changing an XML Element name was not yet implemented. You wanted to change" +
                        " ${referencedElement.nodeName} to ${j.name}")
            }
            //We need to find the text node of it
            val nodeList = referencedElement.childNodes
            for (i in 0 until nodeList.length) {
                val nextNode: Node = nodeList.item(i)
                if (nextNode.nodeType == Node.TEXT_NODE) {
                    nextNode.nodeValue = j.value
                    break
                }
            }
        }
        val tf = TransformerFactory.newInstance()
        val transformer: Transformer = tf.newTransformer()
        //transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        val writer = StringWriter()
        transformer.transform(DOMSource(doc), StreamResult(writer))
        return writer.buffer.toString()
    }

    private fun recursiveExtract(
        all: MutableList<XmlParameter>,
        currentNode: Node,
        path: MutableList<XmlLocator>
    ){
        //First, extract all the attributes of the current element
        for(i in 0 until currentNode.attributes.length){
            val attr = currentNode.attributes.item(i)
            val param = XmlAttrParameter()
            val newPath = path.toMutableList()
            newPath.add(XmlAttributeIndex(i))
            //BurpExtender.println("XmlAttributeIndex: currentNode: ${currentNode.nodeName}, attribute ${attr.nodeName}, i $i")
            param.init(currentNode, attr.nodeName, attr.nodeValue, newPath)
            all.add(param)
        }
        val nodeList = currentNode.childNodes
        var hasChildren = false
        for (i in 0 until nodeList.length) {
            val nextNode: Node = nodeList.item(i)
            if (nextNode.nodeType == Node.ELEMENT_NODE) {
                hasChildren = true
                val newPath = path.toMutableList()
                newPath.add(XmlElementIndex(i))
                //If it is a ELEMENT_NODE we have to recursively unpack
                /*BurpExtender.println("Recursing into: currentNode: ${currentNode.nodeName}, " +
                        "nextNode.name: ${nextNode.nodeName}, newPath: ${newPath.joinToString(", ")}") */
                recursiveExtract(all, nextNode, newPath)
            }
        }
        if(!hasChildren){
            val param = XmlContentParameter()
            for (i in 0 until nodeList.length) {
                val nextNode: Node = nodeList.item(i)
                if (nextNode.nodeType == Node.TEXT_NODE) {
                    /*BurpExtender.println("XmlContentParameter: currentNode.name: ${currentNode.nodeName}, " +
                            "nextNode.value: ${nextNode.nodeValue}"
                    )*/
                    param.init(currentNode, currentNode.nodeName, nextNode.nodeValue, path)
                    all.add(param)
                    break
                }
            }
        }
    }
}