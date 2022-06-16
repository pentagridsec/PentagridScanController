package ch.pentagrid.burpexts.pentagridscancontroller

import burpwrappers.SerializableHttpRequestResponse
import burpwrappers.SerializableHttpService
import java.io.*
import java.util.*
import kotlin.concurrent.thread

open class Persist {

    companion object {

        //Add a toBase64 functionality to ByteArrays
        private fun ByteArray.toBase64(): String = String(Base64.getEncoder().encode(this))
        private fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this)

        private const val host = "pentagrid-ag-scan-controller.local"
        private const val port = 1337
        private const val protocol = "https"

        fun println(s: String){
            BurpExtender.stdout.println(s)
        }

        internal fun saveExtensionSettings(serializableThing: Serializable, name: String){
            //println("Serializing $serializableThing")
            val byteOut = ByteArrayOutputStream()
            val objectOut = ObjectOutputStream(byteOut)
            objectOut.writeObject(serializableThing)
            objectOut.close()
            val bytes = byteOut.toByteArray()
            byteOut.close()
            BurpExtender.c.saveExtensionSetting(name, bytes.toBase64())
        }

        internal fun loadExtensionSettings(name: String): Any? {
            val value = BurpExtender.c.loadExtensionSetting(name)
            return if(value == null){
                null
            }else {
                val serializedThing = value.fromBase64()
                //println("Deserialized $serializedThing")
                val byteIn = ByteArrayInputStream(serializedThing)
                try {
                    val obj = ObjectInputStream(byteIn).readObject()
                    obj
                }catch(e: Exception){
                    println(e)
                    null
                }

            }
        }

        internal fun saveProjectSettings(serializableThing: Serializable, name: String){
            val byteOut = ByteArrayOutputStream()
            val objectOut = ObjectOutputStream(byteOut)
            objectOut.writeObject(serializableThing)
            objectOut.close()
            val bytes = byteOut.toByteArray()
            byteOut.close()
            val request = """GET /$name HTTP/0.9
                |X-Header: You can ignore this item in the site map. It was created by the ${extensionName} extension.
                |X-Header: The Burp extender API does not support project-level settings, so every extension author
                |X-Header: has to abuse this SiteMap storage.
            """.trimMargin().toByteArray()
            val rr = SerializableHttpRequestResponse(request, bytes, null, null,
                SerializableHttpService(host, port, protocol))
            //Do this in a separate thread, as this might deadlock our thread otherwise
            thread(start = true) {
                BurpExtender.c.addToSiteMap(rr)
            }
        }

        internal fun loadProjectSettings(name: String): Any? {
            val rr = BurpExtender.c.getSiteMap("$protocol://$host:$port/$name")
            if(rr.isEmpty()){
                return null
            }
            val serializedThing = rr[0].response
            var obj: Any? = null
            try {
                val byteIn = ByteArrayInputStream(serializedThing)
                obj = ObjectInputStream(byteIn).readObject()
            }catch(ice: InvalidClassException){
                println("Unfortunately deserialization did not work. Probably the extension was updated and the " +
                        "serialVersionUID changed of the objects and differs with the ones stored. " + ice.toString())
            }catch(cnfe: ClassNotFoundException){
                println("Unfortunately deserialization did not work. Probably the extension was updated and the " +
                        "serialVersionUID changed of the objects and differs with the ones stored. " + cnfe.toString())
            }
            return obj
        }


    }
}