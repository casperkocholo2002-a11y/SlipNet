package app.slipnet.tunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream

class EchConfigListInspectorTest {
    @Test fun parsesAuthenticatedRetryPublicName() {
        val list = configList("public.example")
        assertEquals("public.example", EchConfigListInspector.publicName(list))
    }

    @Test fun rejectsMalformedLength() {
        val list = configList("public.example").copyOf()
        list[1] = (list[1].toInt() + 1).toByte()
        assertNull(EchConfigListInspector.publicName(list))
    }

    @Test fun rejectsUnsafePublicName() {
        assertNull(EchConfigListInspector.publicName(configList("bad_name.example")))
    }

    private fun configList(publicName: String): ByteArray {
        val body = ByteArrayOutputStream()
        body.write(1) // config_id
        u16(body, 0x20) // kem_id
        u16(body, 1); body.write(7) // public_key
        u16(body, 4); body.write(byteArrayOf(0, 1, 0, 1))
        body.write(0) // maximum_name_length
        val name = publicName.toByteArray(Charsets.US_ASCII)
        body.write(name.size); body.write(name)
        u16(body, 0) // extensions

        val config = ByteArrayOutputStream()
        u16(config, 0xfe0d)
        u16(config, body.size())
        config.write(body.toByteArray())
        val configBytes = config.toByteArray()

        return ByteArrayOutputStream().also { list ->
            u16(list, configBytes.size)
            list.write(configBytes)
        }.toByteArray()
    }

    private fun u16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xff)
        out.write(value and 0xff)
    }
}
