package ch.pentagrid.burpexts.pentagridscancontroller.helpers

import java.security.MessageDigest


class Md5Set: MutableSet<ByteArray> {

    private val members: MutableSet<ByteArray> = mutableSetOf()

    override val size: Int
        get() = members.size

    override fun contains(element: ByteArray): Boolean {
        return md5(element) in members
    }

    override fun containsAll(elements: Collection<ByteArray>): Boolean {
        return members.containsAll(elements.map{element -> md5(element)})
    }

    override fun isEmpty(): Boolean {
        return members.isEmpty()
    }

    override fun iterator(): MutableIterator<ByteArray> {
        return members.iterator()
    }

    override fun add(element: ByteArray): Boolean {
        return members.add(md5(element))
    }

    override fun addAll(elements: Collection<ByteArray>): Boolean {
        return members.addAll(elements.map{ element -> md5(element)})
    }

    override fun clear() {
        members.clear()
    }

    override fun remove(element: ByteArray): Boolean {
        return members.remove(md5(element))
    }

    override fun removeAll(elements: Collection<ByteArray>): Boolean {
        return members.removeAll(elements.map{ element -> md5(element)}.toSet())
    }

    override fun retainAll(elements: Collection<ByteArray>): Boolean {
        return members.retainAll(elements.map{ element -> md5(element)}.toSet())
    }

    private fun md5(input: ByteArray): ByteArray {
        return MessageDigest.getInstance("MD5").digest(input)
    }

}