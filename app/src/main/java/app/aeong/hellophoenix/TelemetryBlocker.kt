package app.aeong.hellophoenix

import android.util.Log
import io.github.libxposed.api.XposedModule
import java.lang.reflect.AccessibleObject
import java.lang.reflect.Constructor
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.net.URI

private fun String.matchesDomain(domain: String): Boolean = this == domain || endsWith(".$domain")

private fun <T : AccessibleObject> T.accessible(): T = apply { isAccessible = true }

private fun ClassLoader.loadClassOrNull(name: String): Class<*>? =
    runCatching { Class.forName(name, false, this) }.getOrNull()

private fun XposedModule.hookNoop(method: Method) {
    runCatching { hook(method).intercept { null } }
}

object TelemetryBlocker {

    private const val TAG = "HelloPhoenix"
    private val DISCORD_TELEMETRY_PATH = Regex("""^/api(?:/v\d+)?/(?:science|metrics(?:/v2)?|beaker)(?:/.*)?$""")
    private val BLOCKED_HOSTS = setOf("sentry.io", "appsflyer.com", "appsflyersdk.com")
    private val DISCORD_HOSTS = setOf("discord.com", "discordapp.com")
    private val SENTRY_PROVIDERS = arrayOf(
        "io.sentry.android.core.SentryInitProvider",
        "io.sentry.android.core.SentryPerformanceProvider",
    )
    private val APPSFLYER_NOOP_METHODS = setOf(
        "start",
        "logEvent",
        "logSession",
        "sendPushNotificationData",
    )

    fun isBlockedUrl(rawUrl: String): Boolean {
        val uri = runCatching { URI(rawUrl) }.getOrNull() ?: return false
        val host = uri.host?.lowercase() ?: return false
        return when {
            BLOCKED_HOSTS.any(host::matchesDomain) -> true
            DISCORD_HOSTS.any(host::matchesDomain) -> uri.path?.let(DISCORD_TELEMETRY_PATH::matches) == true
            else -> false
        }
    }

    fun install(module: XposedModule, classLoader: ClassLoader, scan: DexScanner.ScanResult) {
        installOkHttpHook(module, classLoader, scan)
        installSentryHooks(module, classLoader, scan)
        installCrashAndTelemetryHooks(module, classLoader, scan)
        installAppsFlyerHooks(module, classLoader)
    }

    private class ResponseFactory(
        private val ctor: Constructor<*>,
        private val requestClass: Class<*>,
        private val protocolClass: Class<*>,
        private val headersClass: Class<*>,
        private val responseBodyClass: Class<*>,
        private val protocol: Any,
        private val emptyHeaders: Any,
        private val emptyBody: Any,
    ) {
        fun noContent(request: Any): Any {
            val now = System.currentTimeMillis()
            val paramTypes = ctor.parameterTypes
            val args = Array<Any?>(paramTypes.size) { index ->
                when (paramTypes[index]) {
                    requestClass -> request
                    protocolClass -> protocol
                    String::class.java -> "No Content"
                    Int::class.javaPrimitiveType -> 204
                    headersClass -> emptyHeaders
                    responseBodyClass -> emptyBody
                    Long::class.javaPrimitiveType -> now
                    else -> null
                }
            }
            return ctor.newInstance(*args)
        }
    }

    private class OkHttpTarget(
        val chainMethod: Method,
        val requestField: Field,
        val urlField: Field,
        val responses: ResponseFactory,
    )

    private fun resolveOkHttpTarget(classLoader: ClassLoader, scan: DexScanner.ScanResult): OkHttpTarget {
        val chainRef = scan.okHttpRealCallChain ?: error("OkHttp RealCall chain method not found")
        val utilDesc = scan.okHttpUtilClass ?: error("OkHttp Util class not found")

        val chainMethod = chainRef.resolve(classLoader) ?: error("Cannot resolve $chainRef")
        val realCallClass = chainMethod.declaringClass
        val responseClass = chainMethod.returnType
        val utilClass = DexScanner.resolveClass(utilDesc, classLoader) ?: error("Cannot resolve $utilDesc")

        val responseCtor = responseClass.declaredConstructors
            .firstOrNull { ctor ->
                val params = ctor.parameterTypes
                params.size >= 11 &&
                    params[1].isEnum &&
                    params[2] == String::class.java &&
                    params[3] == Int::class.javaPrimitiveType
            }
            ?.accessible()
            ?: error("Response constructor not found on ${responseClass.name}")

        val params = responseCtor.parameterTypes
        val requestClass = params[0]
        val protocolClass = params[1]
        val headersClass = params[5]
        val responseBodyClass = params[6]

        val requestField = realCallClass.declaredFields
            .firstOrNull { it.type == requestClass && !Modifier.isStatic(it.modifiers) }
            ?.accessible()
            ?: error("Request field not found on ${realCallClass.name}")

        val urlField = findRequestUrlField(requestClass, headersClass)
            ?: error("URL field not found on ${requestClass.name}")

        val http11 = protocolClass.enumConstants
            ?.firstOrNull { it.toString() == "http/1.1" }
            ?: protocolClass.enumConstants?.firstOrNull()
            ?: error("No Protocol enum constants")

        val emptyHeaders = utilClass.declaredFields
            .firstOrNull { Modifier.isStatic(it.modifiers) && it.type == headersClass }
            ?.accessible()
            ?.get(null)
            ?: headersClass.getDeclaredConstructor(Array<String>::class.java)
                .accessible()
                .newInstance(emptyArray<String>())

        // Response.close() throws IllegalStateException if body is null, so reuse OkHttp's EMPTY_RESPONSE.
        val emptyBody = utilClass.declaredFields
            .firstOrNull {
                Modifier.isStatic(it.modifiers) && responseBodyClass.isAssignableFrom(it.type)
            }
            ?.accessible()
            ?.get(null)
            ?: error("EMPTY_RESPONSE not found on ${utilClass.name}")

        return OkHttpTarget(
            chainMethod = chainMethod,
            requestField = requestField,
            urlField = urlField,
            responses = ResponseFactory(
                ctor = responseCtor,
                requestClass = requestClass,
                protocolClass = protocolClass,
                headersClass = headersClass,
                responseBodyClass = responseBodyClass,
                protocol = http11,
                emptyHeaders = emptyHeaders,
                emptyBody = emptyBody,
            ),
        )
    }

    private fun installOkHttpHook(
        module: XposedModule,
        classLoader: ClassLoader,
        scan: DexScanner.ScanResult,
    ) {
        runCatching {
            val target = resolveOkHttpTarget(classLoader, scan)
            module.hook(target.chainMethod).intercept { chain ->
                val call = chain.thisObject ?: return@intercept chain.proceed()
                val request = target.requestField.get(call) ?: return@intercept chain.proceed()
                val url = target.urlField.get(request)?.toString()
                if (url != null && isBlockedUrl(url)) {
                    return@intercept target.responses.noContent(request)
                }
                chain.proceed()
            }

            listOfNotNull(scan.okHttpRealCallExecute, scan.okHttpAsyncCallRun)
                .forEach { it.resolve(classLoader)?.let(module::deoptimize) }
            module.log(
                Log.INFO,
                TAG,
                "Installed OkHttp telemetry hook on ${target.chainMethod.declaringClass.name}.${target.chainMethod.name}",
            )
        }.onFailure { err ->
            module.log(Log.WARN, TAG, "Failed to install OkHttp telemetry hook", err)
        }
    }

    private fun findRequestUrlField(requestClass: Class<*>, headersClass: Class<*>): Field? {
        val urlType = requestClass.declaredConstructors
            .firstOrNull { it.parameterCount >= 4 }
            ?.parameterTypes
            ?.firstOrNull()
        val instanceFields = requestClass.declaredFields.filter { !Modifier.isStatic(it.modifiers) }
        val matched = if (urlType != null) {
            instanceFields.firstOrNull { it.type == urlType }
        } else {
            instanceFields.firstOrNull {
                it.type != String::class.java &&
                    it.type != headersClass &&
                    !Map::class.java.isAssignableFrom(it.type)
            }
        }
        return matched?.accessible()
    }

    private fun installSentryHooks(
        module: XposedModule,
        classLoader: ClassLoader,
        scan: DexScanner.ScanResult,
    ) {
        for (providerName in SENTRY_PROVIDERS) {
            classLoader.loadClassOrNull(providerName)?.let { cls ->
                runCatching { module.hook(cls.getDeclaredMethod("onCreate")).intercept { true } }
            }
        }
        classLoader.loadClassOrNull("io.sentry.ndk.SentryNdk")?.let { ndk ->
            runCatching { module.hookNoop(ndk.getDeclaredMethod("loadNativeLibraries")) }
        }
        listOfNotNull(scan.sentryAndroidInit, scan.sentryInit)
            .forEach { it.resolve(classLoader)?.let(module::hookNoop) }
    }

    private fun installCrashAndTelemetryHooks(
        module: XposedModule,
        classLoader: ClassLoader,
        scan: DexScanner.ScanResult,
    ) {
        listOfNotNull(scan.crashReporterOutbox, scan.crashReporterSetNonFatal)
            .forEach { it.resolve(classLoader)?.let(module::hookNoop) }

        for (desc in scan.telemetryRingCandidates) {
            val cls = DexScanner.resolveClass(desc, classLoader) ?: continue
            cls.declaredMethods
                .filter {
                    it.parameterCount == 1 &&
                        it.parameterTypes[0] == Boolean::class.javaPrimitiveType &&
                        it.returnType == Void.TYPE
                }
                .forEach { method ->
                    runCatching {
                        module.hook(method).intercept { chain ->
                            if (chain.getArg(0) == true) null else chain.proceed()
                        }
                    }
                }
        }

        classLoader.loadClassOrNull("com.discord.crash_reporting.TelemetryRingModule")
            ?.declaredMethods
            ?.filter { it.name == "append" }
            ?.forEach(module::hookNoop)

        classLoader.loadClassOrNull("com.discord.analytics.touch.TouchEventAnalyticsModule")?.let { cls ->
            runCatching { module.hookNoop(cls.getDeclaredMethod("enableTouchLogging")) }
        }
    }

    private fun installAppsFlyerHooks(module: XposedModule, classLoader: ClassLoader) {
        val appsFlyer = classLoader.loadClassOrNull("com.appsflyer.AppsFlyerLib") ?: return
        for (method in appsFlyer.declaredMethods) {
            when {
                method.name == "init" -> runCatching {
                    module.hook(method).intercept { chain -> chain.thisObject }
                }
                method.name in APPSFLYER_NOOP_METHODS && method.returnType == Void.TYPE ->
                    module.hookNoop(method)
            }
        }
    }
}
