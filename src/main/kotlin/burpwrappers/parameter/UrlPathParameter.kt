package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

const val PARAM_URL_PATH_TYPE: Byte = 0xb0.toByte()

class UrlPathParameter(
    override var value: String,
    val index: Int
) : ParameterAdvanced() {
    override val type: Byte = PARAM_URL_PATH_TYPE
    override val name: String? = null
    override val nameStart: Int = 0
    override val nameEnd: Int = 0
    override val valueStart: Int = 0
    override val valueEnd: Int = 0
    override fun uniqueIdentifier(): String {
        return super.uniqueIdentifier() + ":$index"
    }
}
