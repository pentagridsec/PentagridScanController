package ch.pentagrid.burpexts.pentagridscancontroller.fixer

import ch.pentagrid.burpexts.pentagridscancontroller.LogEntry

class UnixTimestampSecondsValue(override val entry: LogEntry): UnixTimestampMillisecondsValue(entry) {

    override fun now(): Long{
        return System.currentTimeMillis() / 1000
    }

    override fun aroundThreeMonths(): Long{
        return 3.toLong() * 30 * 24 * 60 * 60.toLong()
    }

}