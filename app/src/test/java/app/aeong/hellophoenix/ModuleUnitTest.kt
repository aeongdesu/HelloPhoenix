package app.aeong.hellophoenix

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ModuleUnitTest {

    @Test
    fun blocksTelemetryUrlsAndAllowsNormalApiTraffic() {
        val blockedUrls = listOf(
            "https://discord.com/api/v9/science",
            "https://canary.discord.com/api/v10/metrics",
            "https://ptb.discord.com/api/metrics/v2",
            "https://discord.com/api/beaker?foo=1",
            "https://discordapp.com/api/v9/science",
            "https://o64374.ingest.us.sentry.io/api/4512342174728192/envelope/",
            "https://sentry.io/api/1/store/",
            "https://cdn.appsflyersdk.com/v1/config",
            "https://launches.appsflyer.com/api/v6/androidevent",
        )
        val allowedUrls = listOf(
            "https://discord.com/api/v9/users/@me",
            "https://discord.com/api/v9/channels/123/messages",
            "https://cdn.discordapp.com/avatars/1/2.png",
            "https://example.com/api/v9/science",
            "not a url",
        )
        blockedUrls.forEach { url -> assertTrue("Expected blocked: $url", TelemetryBlocker.isBlockedUrl(url)) }
        allowedUrls.forEach { url -> assertFalse("Expected allowed: $url", TelemetryBlocker.isBlockedUrl(url)) }
    }

    @Test
    fun scansDiscord357203ApkWhenProvided() {
        val apkPath = System.getenv("DISCORD_TEST_APK") ?: return
        val apk = File(apkPath)
        assertTrue("Missing test APK: $apkPath", apk.isFile)

        val scan = DexScanner.scanApk(apk)
        assertNotNull("phoenixLauncher", scan.phoenixLauncher)
        assertEquals("Lcom/discord/phoenix_launch/PhoenixLaunch;", scan.phoenixLauncher?.className)
        assertEquals("Z", scan.phoenixLauncher?.returnType)

        assertNotNull("okHttpRealCallExecute", scan.okHttpRealCallExecute)
        assertNotNull("okHttpRealCallChain", scan.okHttpRealCallChain)
        assertEquals(scan.okHttpRealCallExecute?.className, scan.okHttpRealCallChain?.className)
        assertNotNull("okHttpAsyncCallRun", scan.okHttpAsyncCallRun)
        assertNotNull("okHttpUtilClass", scan.okHttpUtilClass)

        assertNotNull("sentryAndroidInit", scan.sentryAndroidInit)
        assertNotNull("sentryInit", scan.sentryInit)
        assertNotNull("crashReporterOutbox", scan.crashReporterOutbox)
        assertNotNull("crashReporterSetNonFatal", scan.crashReporterSetNonFatal)
        assertTrue("telemetryRingCandidates", scan.telemetryRingCandidates.isNotEmpty())
    }
}
