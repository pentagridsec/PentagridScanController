package burp

/*
 * @(#)ITempFile.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Free Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */
/**
 * This interface is used to hold details of a temporary file that has been
 * created via a call to
 * `IBurpExtenderCallbacks.saveToTempFile()`.
 *
 */
interface ITempFile {
    /**
     * This method is used to retrieve the contents of the buffer that was saved
     * in the temporary file.
     *
     * @return The contents of the buffer that was saved in the temporary file.
     */
    val buffer: ByteArray


    @Deprecated("This method is deprecated and no longer performs any action.")
    fun delete()
}
