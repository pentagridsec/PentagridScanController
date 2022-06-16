package ui

import javax.swing.RowFilter

class HideRowFilter: RowFilter<TableModel, Int>(){

    override fun include(entry: Entry<out TableModel, out Int>): Boolean {
        return !entry.model.isHidden(entry.getStringValue(0).toInt())
    }

}