package ch.pentagrid.burpexts.pentagridscancontroller

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import kotlin.collections.ArrayList

class PersistOverview: Persist() {

    companion object {

        private const val logEntriesName = "logentries"
        private const val settingsName = "settings"

        fun saveSettings(settings: Settings){
            saveExtensionSettings(settings, settingsName)
        }

        @Suppress("UNCHECKED_CAST")
        fun loadSettings(): Settings? {
            val settings = loadExtensionSettings(settingsName)
            return if(settings == null){
                null
            } else{
                settings as Settings
            }
        }

        fun saveLogEntries(entries: List<LogEntry>){
            val entriesClean = mutableListOf<LogEntry>()
            //Start of Test
            //To prevent invalid objects to be stored, we do a test here to serialize each entry and deserialize it again.
            //This is to prevent errors such as:
            //java.io.InvalidObjectException: Malformed URL:  https://example.org:443some.burpcollaborator.net:443
            for(entry in entries) {
                //println("Saving entry.hidden "+ entry.hidden)
                val byteOut = ByteArrayOutputStream()
                val objectOut = ObjectOutputStream(byteOut)
                objectOut.writeObject(entry)
                objectOut.close()
                val bytes = byteOut.toByteArray()
                byteOut.close()
                try {
                    ObjectInputStream(ByteArrayInputStream(bytes)).readObject()
                    entriesClean.add(entry)
                } catch (e: Exception) {
                    println("Could not serialize/deserialize entry and therefore not storing: $entry")
                }
            }
            //End of test
            //Now really save that can be successfully deserialized
            saveProjectSettings(ArrayList(entriesClean), logEntriesName)
        }

        @Suppress("UNCHECKED_CAST")
        fun loadLogEntries(): ArrayList<LogEntry>{
            val entries = loadProjectSettings(logEntriesName)
            return if(entries != null)
                entries as ArrayList<LogEntry>
            else
                ArrayList()
        }

    }
}