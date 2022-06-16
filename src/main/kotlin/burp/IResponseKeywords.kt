package burp

/**
 * This interface is used to represent the counts of keywords appearing in a
 * number of HTTP responses.
 */
interface IResponseKeywords {

    /**
     * This method is used to obtain the list of keywords whose counts vary
     * between the analyzed responses.
     *
     * @return The keywords whose counts vary between the analyzed responses.
     */
    val variantKeywords: List<String>

    /**
     * This method is used to obtain the list of keywords whose counts do not
     * vary between the analyzed responses.
     *
     * @return The keywords whose counts do not vary between the analyzed
     * responses.
     */
    val invariantKeywords: List<String>

    /**
     * This method is used to obtain the number of occurrences of an individual
     * keyword in a response.
     *
     * @param keyword The keyword whose count will be retrieved.
     * @param responseIndex The index of the response. Note responses are
     * indexed from zero in the order they were originally supplied to the
     * `IExtensionHelpers.analyzeResponseKeywords()` and
     * `IResponseKeywords.updateWith()` methods.
     * @return The number of occurrences of the specified keyword for the
     * specified response.
     */
    fun getKeywordCount(keyword: String, responseIndex: Int): Int

    /**
     * This method is used to update the analysis based on additional responses.
     *
     * @param responses The new responses to include in the analysis.
     */
    fun updateWith(vararg responses: ByteArray)
}/*
 * @(#)IResponseKeywords.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
