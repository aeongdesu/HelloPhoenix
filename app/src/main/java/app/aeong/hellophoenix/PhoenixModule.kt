package app.aeong.hellophoenix

import android.util.Log
import io.github.libxposed.api.XposedInterface.PRIORITY_HIGHEST
import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.ModuleLoadedParam
import io.github.libxposed.api.XposedModuleInterface.PackageReadyParam
import java.io.File
import java.lang.reflect.Modifier
import java.util.concurrent.atomic.AtomicBoolean

class PhoenixModule : XposedModule() {

    private val initialized = AtomicBoolean(false)

    override fun onModuleLoaded(param: ModuleLoadedParam) {
        runCatching {
            System.loadLibrary("hellophoenix")
        }.onFailure { err ->
            log(Log.ERROR, TAG, "Failed to load native library", err)
        }
    }

    override fun onPackageReady(param: PackageReadyParam) {
        if (!param.isFirstPackage || !initialized.compareAndSet(false, true)) return

        val apks = buildList {
            param.applicationInfo.sourceDir?.let { add(File(it)) }
            param.applicationInfo.splitSourceDirs
                ?.filter { it.endsWith(".apk") }
                ?.forEach { add(File(it)) }
        }.distinct()

        val scan = DexScanner.scanApks(apks)
        installPhoenixLauncherHook(param.classLoader, scan.phoenixLauncher)
        TelemetryBlocker.install(this, param.classLoader, scan)
    }

    private fun installPhoenixLauncherHook(
        classLoader: ClassLoader,
        launcherRef: DexScanner.MethodRef?,
    ) {
        val method = launcherRef?.resolve(classLoader) ?: run {
            log(Log.WARN, TAG, "Phoenix launcher method not resolved: $launcherRef")
            return
        }

        hook(method).setPriority(PRIORITY_HIGHEST).intercept { true }

        // Prevent ART from inlining the boolean launcher gate into callers on PhoenixLaunch.
        method.declaringClass.declaredMethods
            .filter {
                it != method &&
                    !Modifier.isAbstract(it.modifiers) &&
                    !Modifier.isNative(it.modifiers)
            }
            .forEach(::deoptimize)
        log(Log.INFO, TAG, "Hooked Phoenix launcher ${method.declaringClass.name}.${method.name}")
    }

    private companion object {
        const val TAG = "HelloPhoenix"
    }
}
