package app.slipnet.data.local.database

import android.content.Context
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SlipNetDatabaseMigration44Test {
    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "migration-43-44-direct.db"
    private val factory = FrameworkSQLiteOpenHelperFactory()

    @Test
    fun migration43To44AddsBlankEchSeedWithoutTouchingProfile() {
        context.deleteDatabase(dbName)
        try {
            createV43().use { it.writableDatabase.execSQL("INSERT INTO server_profiles(id,name) VALUES(7,'preserve-me')") }
            openV44().use { helper ->
                val db = helper.writableDatabase
                val columns = mutableMapOf<String, Pair<String?, Int>>()
                db.query("PRAGMA table_info(server_profiles)").use { c ->
                    val n=c.getColumnIndexOrThrow("name"); val d=c.getColumnIndexOrThrow("dflt_value"); val nn=c.getColumnIndexOrThrow("notnull")
                    while(c.moveToNext()) columns[c.getString(n)] = c.getString(d) to c.getInt(nn)
                }
                assertEquals("''", columns.getValue("vless_ech_config_seed").first)
                assertEquals("0", columns.getValue("vless_ech_config_updated_at").first)
                assertEquals(1, columns.getValue("vless_ech_config_seed").second)
                db.query("SELECT id,name,vless_ech_config_seed,vless_ech_config_updated_at FROM server_profiles WHERE id=7").use { c ->
                    assertTrue(c.moveToFirst()); assertEquals(7L,c.getLong(0)); assertEquals("preserve-me",c.getString(1)); assertEquals("",c.getString(2)); assertEquals(0L,c.getLong(3))
                }
            }
        } finally { context.deleteDatabase(dbName) }
    }

    private fun createV43(): SupportSQLiteOpenHelper = factory.create(
        SupportSQLiteOpenHelper.Configuration.builder(context).name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(43) {
                override fun onCreate(db: SupportSQLiteDatabase) {
                    db.execSQL("CREATE TABLE server_profiles (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL)")
                }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = Unit
            }).build()
    )

    private fun openV44(): SupportSQLiteOpenHelper = factory.create(
        SupportSQLiteOpenHelper.Configuration.builder(context).name(dbName)
            .callback(object : SupportSQLiteOpenHelper.Callback(44) {
                override fun onCreate(db: SupportSQLiteDatabase) = Unit
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(43, oldVersion)
                    assertEquals(44, newVersion)
                    SlipNetDatabase.MIGRATION_43_44.migrate(db)
                }
            }).build()
    )
}
