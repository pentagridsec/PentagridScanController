package burp

/*
 * @(#)IExtensionHelpers.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.net.URL

/**
 * This interface contains a number of helper methods, which extensions can use
 * to assist with various common tasks that arise for Burp extensions.
 *
 * Extensions can call `IBurpExtenderCallbacks.getHelpers` to obtain
 * an instance of this interface.
 */
interface IExtensionHelpers {

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it.
     *
     * @param request An `IHttpRequestResponse` object containing the
     * request to be analyzed.
     * @return An `IRequestInfo` object that can be queried to obtain
     * details about the request.
     */
    fun analyzeRequest(request: IHttpRequestResponse): IRequestInfo

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it.
     *
     * @param httpService The HTTP service associated with the request. This is
     * optional and may be `null`, in which case the resulting
     * `IRequestInfo` object will not include the full request URL.
     * @param request The request to be analyzed.
     * @return An `IRequestInfo` object that can be queried to obtain
     * details about the request.
     */
    fun analyzeRequest(httpService: IHttpService, request: ByteArray): IRequestInfo

    /**
     * This method can be used to analyze an HTTP request, and obtain various
     * key details about it. The resulting `IRequestInfo` object will
     * not include the full request URL. To obtain the full URL, use one of the
     * other overloaded `analyzeRequest()` methods.
     *
     * @param request The request to be analyzed.
     * @return An `IRequestInfo` object that can be queried to obtain
     * details about the request.
     */
    fun analyzeRequest(request: ByteArray): IRequestInfo

    /**
     * This method can be used to analyze an HTTP response, and obtain various
     * key details about it.
     *
     * @param response The response to be analyzed.
     * @return An `IResponseInfo` object that can be queried to
     * obtain details about the response.
     */
    fun analyzeResponse(response: ByteArray): IResponseInfo

    /**
     * This method can be used to retrieve details of a specified parameter
     * within an HTTP request. **Note:** Use `analyzeRequest()` to
     * obtain details of all parameters within the request.
     *
     * @param request The request to be inspected for the specified parameter.
     * @param parameterName The name of the parameter to retrieve.
     * @return An `IParameter` object that can be queried to obtain
     * details about the parameter, or `null` if the parameter was
     * not found.
     */
    fun getRequestParameter(request: ByteArray, parameterName: String): IParameter

    /**
     * This method can be used to URL-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    fun urlDecode(data: String): String

    /**
     * This method can be used to URL-encode the specified data. Any characters
     * that do not need to be encoded within HTTP requests are not encoded.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    fun urlEncode(data: String): String

    /**
     * This method can be used to URL-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    fun urlDecode(data: ByteArray): ByteArray

    /**
     * This method can be used to URL-encode the specified data. Any characters
     * that do not need to be encoded within HTTP requests are not encoded.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    fun urlEncode(data: ByteArray): ByteArray

    /**
     * This method can be used to Base64-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    fun base64Decode(data: String): ByteArray

    /**
     * This method can be used to Base64-decode the specified data.
     *
     * @param data The data to be decoded.
     * @return The decoded data.
     */
    fun base64Decode(data: ByteArray): ByteArray

    /**
     * This method can be used to Base64-encode the specified data.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    fun base64Encode(data: String): String

    /**
     * This method can be used to Base64-encode the specified data.
     *
     * @param data The data to be encoded.
     * @return The encoded data.
     */
    fun base64Encode(data: ByteArray): String

    /**
     * This method can be used to convert data from String form into an array of
     * bytes. The conversion does not reflect any particular character set, and
     * a character with the hex representation 0xWXYZ will always be converted
     * into a byte with the representation 0xYZ. It performs the opposite
     * conversion to the method `bytesToString()`, and byte-based
     * data that is converted to a String and back again using these two methods
     * is guaranteed to retain its integrity (which may not be the case with
     * conversions that reflect a given character set).
     *
     * @param data The data to be converted.
     * @return The converted data.
     */
    fun stringToBytes(data: String): ByteArray

    /**
     * This method can be used to convert data from an array of bytes into
     * String form. The conversion does not reflect any particular character
     * set, and a byte with the representation 0xYZ will always be converted
     * into a character with the hex representation 0x00YZ. It performs the
     * opposite conversion to the method `stringToBytes()`, and
     * byte-based data that is converted to a String and back again using these
     * two methods is guaranteed to retain its integrity (which may not be the
     * case with conversions that reflect a given character set).
     *
     * @param data The data to be converted.
     * @return The converted data.
     */
    fun bytesToString(data: ByteArray): String

    /**
     * This method searches a piece of data for the first occurrence of a
     * specified pattern. It works on byte-based data in a way that is similar
     * to the way the native Java method `String.indexOf()` works on
     * String-based data.
     *
     * @param data The data to be searched.
     * @param pattern The pattern to be searched for.
     * @param caseSensitive Flags whether or not the search is case-sensitive.
     * @param from The offset within `data` where the search should
     * begin.
     * @param to The offset within `data` where the search should
     * end.
     * @return The offset of the first occurrence of the pattern within the
     * specified bounds, or -1 if no match is found.
     */
    fun indexOf(data: ByteArray,
                pattern: ByteArray,
                caseSensitive: Boolean,
                from: Int,
                to: Int): Int

    /**
     * This method builds an HTTP message containing the specified headers and
     * message body. If applicable, the Content-Length header will be added or
     * updated, based on the length of the body.
     *
     * @param headers A list of headers to include in the message.
     * @param body The body of the message, of `null` if the message
     * has an empty body.
     * @return The resulting full HTTP message.
     */
    fun buildHttpMessage(headers: List<String>, body: ByteArray): ByteArray

    /**
     * This method creates a GET request to the specified URL. The headers used
     * in the request are determined by the Request headers settings as
     * configured in Burp Spider's options.
     *
     * @param url The URL to which the request should be made.
     * @return A request to the specified URL.
     */
    fun buildHttpRequest(url: URL): ByteArray

    /**
     * This method adds a new parameter to an HTTP request, and if appropriate
     * updates the Content-Length header.
     *
     * @param request The request to which the parameter should be added.
     * @param parameter An `IParameter` object containing details of
     * the parameter to be added. Supported parameter types are:
     * `PARAM_URL`, `PARAM_BODY` and
     * `PARAM_COOKIE`.
     * @return A new HTTP request with the new parameter added.
     */
    fun addParameter(request: ByteArray, parameter: IParameter): ByteArray

    /**
     * This method removes a parameter from an HTTP request, and if appropriate
     * updates the Content-Length header.
     *
     * @param request The request from which the parameter should be removed.
     * @param parameter An `IParameter` object containing details of
     * the parameter to be removed. Supported parameter types are:
     * `PARAM_URL`, `PARAM_BODY` and
     * `PARAM_COOKIE`.
     * @return A new HTTP request with the parameter removed.
     */
    fun removeParameter(request: ByteArray, parameter: IParameter): ByteArray

    /**
     * This method updates the value of a parameter within an HTTP request, and
     * if appropriate updates the Content-Length header. **Note:** This
     * method can only be used to update the value of an existing parameter of a
     * specified type. If you need to change the type of an existing parameter,
     * you should first call `removeParameter()` to remove the
     * parameter with the old type, and then call `addParameter()` to
     * add a parameter with the new type.
     *
     * @param request The request containing the parameter to be updated.
     * @param parameter An `IParameter` object containing details of
     * the parameter to be updated. Supported parameter types are:
     * `PARAM_URL`, `PARAM_BODY` and
     * `PARAM_COOKIE`.
     * @return A new HTTP request with the parameter updated.
     */
    fun updateParameter(request: ByteArray, parameter: IParameter): ByteArray

    /**
     * This method can be used to toggle a request's method between GET and
     * POST. Parameters are relocated between the URL query string and message
     * body as required, and the Content-Length header is created or removed as
     * applicable.
     *
     * @param request The HTTP request whose method should be toggled.
     * @return A new HTTP request using the toggled method.
     */
    fun toggleRequestMethod(request: ByteArray): ByteArray

    /**
     * This method constructs an `IHttpService` object based on the
     * details provided.
     *
     * @param host The HTTP service host.
     * @param port The HTTP service port.
     * @param protocol The HTTP service protocol.
     * @return An `IHttpService` object based on the details
     * provided.
     */
    fun buildHttpService(host: String, port: Int, protocol: String): IHttpService

    /**
     * This method constructs an `IHttpService` object based on the
     * details provided.
     *
     * @param host The HTTP service host.
     * @param port The HTTP service port.
     * @param useHttps Flags whether the HTTP service protocol is HTTPS or HTTP.
     * @return An `IHttpService` object based on the details
     * provided.
     */
    fun buildHttpService(host: String, port: Int, useHttps: Boolean): IHttpService

    /**
     * This method constructs an `IParameter` object based on the
     * details provided.
     *
     * @param name The parameter name.
     * @param value The parameter value.
     * @param type The parameter type, as defined in the `IParameter`
     * interface.
     * @return An `IParameter` object based on the details provided.
     */
    fun buildParameter(name: String, value: String, type: Byte): IParameter

    /**
     * This method constructs an `IScannerInsertionPoint` object
     * based on the details provided. It can be used to quickly create a simple
     * insertion point based on a fixed payload location within a base request.
     *
     * @param insertionPointName The name of the insertion point.
     * @param baseRequest The request from which to build scan requests.
     * @param from The offset of the start of the payload location.
     * @param to The offset of the end of the payload location.
     * @return An `IScannerInsertionPoint` object based on the
     * details provided.
     */
    fun makeScannerInsertionPoint(
            insertionPointName: String,
            baseRequest: ByteArray,
            from: Int,
            to: Int): IScannerInsertionPoint

    /**
     * This method analyzes one or more responses to identify variations in a
     * number of attributes and returns an `IResponseVariations`
     * object that can be queried to obtain details of the variations.
     *
     * @param responses The responses to analyze.
     * @return An `IResponseVariations` object representing the
     * variations in the responses.
     */
    fun analyzeResponseVariations(vararg responses: ByteArray): IResponseVariations

    /**
     * This method analyzes one or more responses to identify the number of
     * occurrences of the specified keywords and returns an
     * `IResponseKeywords` object that can be queried to obtain
     * details of the number of occurrences of each keyword.
     *
     * @param keywords The keywords to look for.
     * @param responses The responses to analyze.
     * @return An `IResponseKeywords` object representing the counts
     * of the keywords appearing in the responses.
     */
    fun analyzeResponseKeywords(keywords: List<String>, vararg responses: ByteArray): IResponseKeywords
}
