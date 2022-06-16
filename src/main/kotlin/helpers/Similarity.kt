package ch.pentagrid.burpexts.pentagridscancontroller.helpers

import ch.pentagrid.burpexts.pentagridscancontroller.BurpExtender
import java.lang.Integer.min
import kotlin.system.measureTimeMillis

class Similarity {

    companion object {

        private fun println(s: String){
            BurpExtender.stdout.println(s)
        }

        //bcount is an argument that can be supplied to improve performance
        //It would be possible to also create an acount, which would optimize performance
        //for comparing, but only if we would compare something we compared before with something
        //we also compared before. However, our use case is to compare something we compared before
        //with something new, so as long as "b" is always the "something we compared before" there is
        //nothing to improve.
        //This is a performance to memory tradeoff, but the structures don't get very big.
        fun isSimilar(a: ByteArray, b: ByteArray, minimum_similarity: Double, bByteCount: Map<Byte, Int>?):
                Pair<Boolean, Map<Byte, Int>?> {
            //Checks only the length to check if they could be similar
            //then checks the Characters (aka Byte) if they could be similar.
            //According to this class ABBA and BAAB and BABA are all the same (1.0 similarity)
            var bByteCountNew = bByteCount
            if(a.contentEquals(b)){
                return Pair(true, bByteCountNew)
            }
            if(minimum_similarity > veryQuickRatio(a, b)){
                if(BurpExtender.ui.settings.debug){
                    println("Similarity.veryQuickRatio did the trick in no time")
                }
                return Pair(false, bByteCountNew)
            }else{
                val res: Pair<Double, Map<Byte, Int>>
                val elapsed = measureTimeMillis {
                    res = quickRatio(a, b, bByteCount)
                }
                val (ratio, bcountReturn) = res
                bByteCountNew = bcountReturn
                if(elapsed > 150 || BurpExtender.ui.settings.debug){
                    println("Similarity.quickRatio elapsed time: ${elapsed}ms, length a: ${a.size}, " +
                            "length b: ${b.size}, " +
                            "precalculated bByteCount: ${bByteCount != null}, " +
                            "length of keys bByteCountNew: ${bByteCountNew.size}/256")
                }
                if(minimum_similarity > ratio){
                    return Pair(false, bByteCountNew)
                }
            }
            return Pair(true, bByteCountNew)
        }

        private fun quickRatio(a: ByteArray, b: ByteArray, bByteCountPrecalculated: Map<Byte, Int>?): Pair<Double, Map<Byte, Int>> {
            // A ratio where only the character count (aka Byte), but not their position/order
            var bcount = bByteCountPrecalculated
            if(bcount == null) {
                val bByteCountCalc = mutableMapOf<Byte, Int>()
                for (Byteacter in b) {
                    bByteCountCalc[Byteacter] = bByteCountCalc.getOrDefault(Byteacter, 0) + 1
                }
                bcount = bByteCountCalc.toMap()
            }

            val avail = mutableMapOf<Byte, Int>()
            var matches = 0
            for(character in a){
                val numb = if(avail.containsKey(character)) {
                    avail.getOrDefault(character, 0)
                }else{
                    bcount.getOrDefault(character, 0)
                }
                avail[character] = numb - 1
                if(numb > 0){
                    matches += 1
                }
            }
            return Pair(calculateRatio(matches, a.size + b.size), bcount)
        }

        private fun veryQuickRatio(a: ByteArray, b: ByteArray): Double {
            // A ratio where only the length of the strings counts
            val la = a.size
            val lb = b.size
            return calculateRatio(min(la, lb), la + lb)
        }

        private fun calculateRatio(matches: Int, length: Int): Double {
            return 2.0 * matches / length
        }


    }
}