package burp

/*
 * @(#)IParameter.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details about an HTTP request parameter.
 */
interface IParameter {

    /**
     * This method is used to retrieve the parameter type.
     *
     * @return The parameter type. The available types are defined within this
     * interface.
     */
    val type: Byte

    /**
     * This method is used to retrieve the parameter name.
     *
     * @return The parameter name.
     */
    val name: String?

    /**
     * This method is used to retrieve the parameter value.
     *
     * @return The parameter value.
     */
    val value: String

    /**
     * This method is used to retrieve the start offset of the parameter name
     * within the HTTP request.
     *
     * @return The start offset of the parameter name within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    val nameStart: Int

    /**
     * This method is used to retrieve the end offset of the parameter name
     * within the HTTP request.
     *
     * @return The end offset of the parameter name within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    val nameEnd: Int

    /**
     * This method is used to retrieve the start offset of the parameter value
     * within the HTTP request.
     *
     * @return The start offset of the parameter value within the HTTP request,
     * or -1 if the parameter is not associated with a specific request.
     */
    val valueStart: Int

    /**
     * This method is used to retrieve the end offset of the parameter value
     * within the HTTP request.
     *
     * @return The end offset of the parameter value within the HTTP request, or
     * -1 if the parameter is not associated with a specific request.
     */
    val valueEnd: Int

    companion object {
        /**
         * Used to indicate a parameter within the URL query string.
         */
        const val PARAM_URL: Byte = 0
        /**
         * Used to indicate a parameter within the message body.
         */
        const val PARAM_BODY: Byte = 1
        /**
         * Used to indicate an HTTP cookie.
         */
        const val PARAM_COOKIE: Byte = 2
        /**
         * Used to indicate an item of data within an XML structure.
         */
        const val PARAM_XML: Byte = 3
        /**
         * Used to indicate the value of a tag attribute within an XML structure.
         */
        const val PARAM_XML_ATTR: Byte = 4
        /**
         * Used to indicate the value of a parameter attribute within a multi-part
         * message body (such as the name of an uploaded file).
         */
        const val PARAM_MULTIPART_ATTR: Byte = 5
        /**
         * Used to indicate an item of data within a JSON structure.
         */
        const val PARAM_JSON: Byte = 6
    }
}
