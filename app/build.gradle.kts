import org.gradle.api.GradleException
import java.io.File
import java.util.Properties

plugins {
    alias(libs.plugins.agp.app)
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropertiesFile.isFile) {
        keystorePropertiesFile.inputStream().use(::load)
    }
}

fun signingValue(envKey: String, propKey: String): String? =
    System.getenv(envKey)?.takeIf { it.isNotBlank() }
        ?: keystoreProps.getProperty(propKey)?.trim()?.takeIf { it.isNotEmpty() }

val explicitStoreFile = signingValue("SIGNING_STORE_FILE", "storeFile")
val signingStorePassword = signingValue("SIGNING_STORE_PASSWORD", "storePassword")
val signingKeyAlias = signingValue("SIGNING_KEY_ALIAS", "keyAlias")
val signingKeyPassword = signingValue("SIGNING_KEY_PASSWORD", "keyPassword") ?: signingStorePassword
val signingStoreFile = explicitStoreFile?.let { path ->
    if (path.startsWith("~/")) {
        File(System.getProperty("user.home"), path.removePrefix("~/"))
    } else {
        rootProject.file(path)
    }
} ?: File(System.getProperty("user.home"), "aeong.jks")

val signingConfigured = explicitStoreFile != null ||
    signingStorePassword != null ||
    signingKeyAlias != null ||
    signingKeyPassword != null ||
    keystorePropertiesFile.isFile
val hasReleaseSigning = signingStoreFile.isFile &&
    signingStorePassword != null &&
    signingKeyAlias != null &&
    signingKeyPassword != null

if (signingConfigured && !hasReleaseSigning) {
    val missing = buildList {
        if (!signingStoreFile.isFile) add("keystore file (${signingStoreFile.path})")
        if (signingStorePassword == null) add("storePassword / SIGNING_STORE_PASSWORD")
        if (signingKeyAlias == null) add("keyAlias / SIGNING_KEY_ALIAS")
        if (signingKeyPassword == null) add("keyPassword / SIGNING_KEY_PASSWORD")
    }
    throw GradleException("Incomplete release signing configuration: missing ${missing.joinToString(", ")}")
}

android {
    namespace = "app.aeong.hellophoenix"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "app.aeong.hellophoenix"
        minSdk = 28
        targetSdk = 37
        versionCode = providers.gradleProperty("versionCode").orNull?.toIntOrNull() ?: 1
        versionName = providers.gradleProperty("versionName").orNull?.takeIf { it.isNotBlank() } ?: "1.0.0"

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = signingStoreFile
                storePassword = signingStorePassword
                keyAlias = signingKeyAlias
                keyPassword = signingKeyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles("proguard-rules.pro")
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.31.6"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
        resources {
            merges += "META-INF/xposed/*"
            excludes += "**"
        }
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = false
    }
}

dependencies {
    compileOnly(libs.libxposed.api)
    testImplementation(libs.junit)
}
