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
class SlipNetDatabaseMigration43Test {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val dbName = "migration-42-43-direct.db"
    private val factory = FrameworkSQLiteOpenHelperFactory()

    @Test
    fun migration42To43AddsBlankFailureDomainMetadataWithoutGuessing() {
        context.deleteDatabase(dbName)
        try {
            createVersion42Database().use { helper ->
                helper.writableDatabase.execSQL(
                    "INSERT INTO server_profiles(id, name) VALUES(7, 'preserve-me')"
                )
            }

            openVersion43Database().use { helper ->
                val db = helper.writableDatabase
                val columns = mutableMapOf<String, Pair<String?, Int>>()
                db.query("PRAGMA table_info(server_profiles)").use { cursor ->
                    val name = cursor.getColumnIndexOrThrow("name")
                    val defaultValue = cursor.getColumnIndexOrThrow("dflt_value")
                    val notNull = cursor.getColumnIndexOrThrow("notnull")
                    while (cursor.moveToNext()) {
                        columns[cursor.getString(name)] =
                            cursor.getString(defaultValue) to cursor.getInt(notNull)
                    }
                }
                listOf(
                    "vless_failure_provider_id",
                    "vless_failure_account_id",
                    "vless_failure_hostname",
                ).forEach { column ->
                    assertTrue("missing $column", columns.containsKey(column))
                    assertEquals("''", columns.getValue(column).first)
                    assertEquals(1, columns.getValue(column).second)
                }

                db.query(
                    "SELECT id, name, vless_failure_provider_id, " +
                        "vless_failure_account_id, vless_failure_hostname " +
                        "FROM server_profiles WHERE id=7"
                ).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertEquals(7L, cursor.getLong(0))
                    assertEquals("preserve-me", cursor.getString(1))
                    assertEquals("", cursor.getString(2))
                    assertEquals("", cursor.getString(3))
                    assertEquals("", cursor.getString(4))
                }
            }
        } finally {
            context.deleteDatabase(dbName)
        }
    }

    private fun createVersion42Database(): SupportSQLiteOpenHelper =
        factory.create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(dbName)
                .callback(object : SupportSQLiteOpenHelper.Callback(42) {
                    override fun onCreate(db: SupportSQLiteDatabase) {
                        db.execSQL(
                            "CREATE TABLE server_profiles (" +
                                "id INTEGER PRIMARY KEY NOT NULL, " +
                                "name TEXT NOT NULL)"
                        )
                    }

                    override fun onUpgrade(
                        db: SupportSQLiteDatabase,
                        oldVersion: Int,
                        newVersion: Int,
                    ) = Unit
                })
                .build()
        )

    private fun openVersion43Database(): SupportSQLiteOpenHelper =
        factory.create(
            SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(dbName)
                .callback(object : SupportSQLiteOpenHelper.Callback(43) {
                    override fun onCreate(db: SupportSQLiteDatabase) = Unit

                    override fun onUpgrade(
                        db: SupportSQLiteDatabase,
                        oldVersion: Int,
                        newVersion: Int,
                    ) {
                        assertEquals(42, oldVersion)
                        assertEquals(43, newVersion)
                        SlipNetDatabase.MIGRATION_42_43.migrate(db)
                    }
                })
                .build()
        )
}
