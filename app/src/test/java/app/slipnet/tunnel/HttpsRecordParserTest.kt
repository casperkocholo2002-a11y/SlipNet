package app.slipnet.tunnel

import java.io.ByteArrayOutputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class HttpsRecordParserTest {
    @Test
    fun extractsEchConfigFromHttpsAnswer() {
        val ech = byteArrayOf(0x00, 0x08, 0xFE.toByte(), 0x0D, 0x01, 0x02, 0x03, 0x04)
        val packet = dnsResponse(ech)

        assertArrayEquals(ech, HttpsRecordParser.extractEchConfigList(packet))
    }

    @Test
    fun returnsNullForMalformedRdataLength() {
        val packet = dnsResponse(byteArrayOf(1, 2, 3)).copyOf().also {
            val rdLengthOffset = findRdLengthOffset(it)
            it[rdLengthOffset] = 0x7F
            it[rdLengthOffset + 1] = 0x7F
        }
        assertNull(HttpsRecordParser.extractEchConfigList(packet))
    }

    private fun dnsResponse(ech: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, 0x1234)
        writeU16(out, 0x8180)
        writeU16(out, 1)
        writeU16(out, 1)
        writeU16(out, 0)
        writeU16(out, 0)
        writeName(out, "example.com")
        writeU16(out, 65)
        writeU16(out, 1)

        writeU16(out, 0xC00C)
        writeU16(out, 65)
        writeU16(out, 1)
        writeU32(out, 60)

        val rdata = ByteArrayOutputStream()
        writeU16(rdata, 1)
        rdata.write(0)
        writeU16(rdata, 1)
        writeU16(rdata, 3)
        rdata.write(byteArrayOf(2, 'h'.code.toByte(), '2'.code.toByte()))
        writeU16(rdata, 5)
        writeU16(rdata, ech.size)
        rdata.write(ech)

        val bytes = rdata.toByteArray()
        writeU16(out, bytes.size)
        out.write(bytes)
        return out.toByteArray()
    }

    private fun findRdLengthOffset(packet: ByteArray): Int {
        var offset = 12
        offset = skipName(packet, offset) + 4
        offset = skipName(packet, offset)
        return offset + 8
    }

    private fun skipName(packet: ByteArray, start: Int): Int {
        var offset = start
        while (true) {
            val len = packet[offset].toInt() and 0xFF
            if (len == 0) return offset + 1
            if (len and 0xC0 == 0xC0) return offset + 2
            offset += 1 + len
        }
    }

    private fun writeName(out: ByteArrayOutputStream, name: String) {
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}
