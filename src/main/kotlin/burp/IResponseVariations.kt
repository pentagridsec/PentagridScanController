package burp

/**
 * This interface is used to represent variations between a number HTTP
 * responses, according to various attributes.
 */
interface IResponseVariations {

    /**
     * This method is used to obtain the list of attributes that vary between
     * the analyzed responses.
     *
     * @return The attributes that vary between the analyzed responses.
     */
    val variantAttributes: List<String>

    /**
     * This method is used to obtain the list of attributes that do not vary
     * between the analyzed responses.
     *
     * @return The attributes that do not vary between the analyzed responses.
     */
    val invariantAttributes: List<String>

    /**
     * This method is used to obtain the value of an individual attribute in a
     * response. Note that the values of some attributes are intrinsically
     * meaningful (e.g. a word count) while the values of others are less so
     * (e.g. a checksum of the HTML tag names).
     *
     * @param attributeName The name of the attribute whose value will be
     * retrieved. Extension authors can obtain the list of supported attributes
     * by generating an `IResponseVariations` object for a single
     * response and calling
     * `IResponseVariations.getInvariantAttributes()`.
     * @param responseIndex The index of the response. Note that responses are
     * indexed from zero in the order they were originally supplied to the
     * `IExtensionHelpers.analyzeResponseVariations()` and
     * `IResponseVariations.updateWith()` methods.
     * @return The value of the specified attribute for the specified response.
     */
    fun getAttributeValue(attributeName: String, responseIndex: Int): Int

    /**
     * This method is used to update the analysis based on additional responses.
     *
     * @param responses The new responses to include in the analysis.
     */
    fun updateWith(vararg responses: ByteArray)
}/*
 * @(#)IResponseVariations.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
