package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

const val PARAM_MULTIPART_FILENAME: Byte = 0xb2.toByte() // Content-Disposition: form-data; name="paramname"; filename="up.jpeg"
const val PARAM_MULTIPART_CONTENT: Byte = 0xb1.toByte() /*
Content-Disposition: form-data; name="whatever"

value
*/

abstract class MultipartParameter(
    override var name: String?,
    override var value: String,
    open val multipartIndex: Int
) : ParameterAdvanced() {
    override val type: Byte = PARAM_URL_PATH_TYPE
    override val nameStart: Int = 0
    override val nameEnd: Int = 0
    override val valueStart: Int = 0
    override val valueEnd: Int = 0
    override fun uniqueIdentifier(): String {
        return super.uniqueIdentifier() + ":$multipartIndex"
    }
}


class MultipartFilename(
    override var name: String?,
    override var value: String,
    override val multipartIndex: Int
): MultipartParameter(name, value, multipartIndex) {
    override val type: Byte = PARAM_MULTIPART_FILENAME
}

class MultipartContent(
    override var name: String?,
    override var value: String,
    override val multipartIndex: Int
): MultipartParameter(name, value, multipartIndex) {
    override val type: Byte = PARAM_MULTIPART_CONTENT
}