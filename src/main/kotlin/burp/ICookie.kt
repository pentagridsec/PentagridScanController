package burp

/*
 * @(#)ICookie.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
import java.util.Date

/**
 * This interface is used to hold details about an HTTP cookie.
 */
interface ICookie {
    /**
     * This method is used to retrieve the domain for which the cookie is in
     * scope.
     *
     * @return The domain for which the cookie is in scope. **Note:** For
     * cookies that have been analyzed from responses (by calling
     * `IExtensionHelpers.analyzeResponse()` and then
     * `IResponseInfo.getCookies()`, the domain will be
     * `null` if the response did not explicitly set a domain
     * attribute for the cookie.
     */
    val domain: String?

    /**
     * This method is used to retrieve the path for which the cookie is in
     * scope.
     *
     * @return The path for which the cookie is in scope or null if none is set.
     */
    val path: String?

    /**
     * This method is used to retrieve the expiration time for the cookie.
     *
     * @return The expiration time for the cookie, or
     * `null` if none is set (i.e., for non-persistent session
     * cookies).
     */
    val expiration: Date?

    /**
     * This method is used to retrieve the name of the cookie.
     *
     * @return The name of the cookie.
     */
    val name: String

    /**
     * This method is used to retrieve the value of the cookie.
     * @return The value of the cookie.
     */
    val value: String
}
