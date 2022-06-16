package ch.pentagrid.burpexts.pentagridscancontroller.burpwrappers.parameter

const val PARAM_NON_STANDARD_HEADER_TYPE: Byte = 0xb3.toByte()

class NonStandardHeaderParameter(
    override var name: String? = null,
    override var value: String,
) : ParameterAdvanced() {
    override val type: Byte = PARAM_NON_STANDARD_HEADER_TYPE
    override val nameStart: Int = 0
    override val nameEnd: Int = 0
    override val valueStart: Int = 0
    override val valueEnd: Int = 0
}
