package ch.pentagrid.burpexts.pentagridscancontroller.helpers


internal object Combiner {

    fun combinationsOneEach(input: List<List<Int>>): List<List<Int>> {
        return cartesianProduct(*input.map { it }.toTypedArray())
    }

    fun cartesianProduct(vararg lists: List<Int>): List<List<Int>> =
        lists.fold(listOf(listOf())) { acc, outerList ->
                acc.flatMap { innerList -> outerList.map { element -> innerList + element } }
            }

    /*
    Create all combinations of integers
    Input [0, 1, 2] will produce:
    []
    [1, 2, 3]
    [0, 1]
    [0, 2]
    [1, 2]
    [0]
    [1]
    [2]
    */
    fun allCombinations(input: List<Int>, desiredLength: Int = 0): List<List<Int>> {
        val arr = input.toIntArray()
        val all: MutableList<List<Int>> = mutableListOf(emptyList())
        val length = if(desiredLength == 0) {
            arr.size
        }else {
            desiredLength
        }
        for(i in length downTo  1)
            combinerRecursive(all, arr, IntArray(i), 0, length - 1, 0, i)
        return all
    }

    private fun combinerRecursive(all: MutableList<List<Int>>,
                                  originalData: IntArray, currentData: IntArray, start: Int,
                                  end: Int, index: Int, desiredLength: Int
    ) {
        if (index == desiredLength) {
            all.add(currentData.toList())
            return
        }
        var i = start
        while (i <= end && end - i + 1 >= desiredLength - index) {
            currentData[index] = originalData[i]
            combinerRecursive(all, originalData, currentData, i + 1, end, index + 1, desiredLength)
            i+=1
        }
    }
}