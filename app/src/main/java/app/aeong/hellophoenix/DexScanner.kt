package app.aeong.hellophoenix

import java.io.File
import java.lang.reflect.Method
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipFile

object DexScanner {

    data class MethodRef(
        val className: String,
        val methodName: String,
        val parameterTypes: List<String>,
        val returnType: String,
    ) {
        fun resolve(classLoader: ClassLoader): Method? {
            val clazz = resolveClass(className, classLoader) ?: return null
            val paramClasses = parameterTypes.map { resolveClass(it, classLoader) ?: return null }
            return runCatching {
                clazz.getDeclaredMethod(methodName, *paramClasses.toTypedArray()).apply {
                    isAccessible = true
                }
            }.getOrNull()
        }
    }

    data class ScanResult(
        val phoenixLauncher: MethodRef? = null,
        val okHttpRealCallExecute: MethodRef? = null,
        val okHttpRealCallChain: MethodRef? = null,
        val okHttpAsyncCallRun: MethodRef? = null,
        val okHttpUtilClass: String? = null,
        val sentryAndroidInit: MethodRef? = null,
        val sentryInit: MethodRef? = null,
        val crashReporterOutbox: MethodRef? = null,
        val crashReporterSetNonFatal: MethodRef? = null,
        val telemetryRingCandidates: List<String> = emptyList(),
    )

    private const val MASK_PHOENIX_LAUNCH = 1 shl 0
    private const val MASK_ALREADY_EXECUTED = 1 shl 1
    private const val MASK_CANCELED = 1 shl 2
    private const val MASK_OKHTTP_PREFIX = 1 shl 3
    private const val MASK_CANCELED_DUE_TO = 1 shl 4
    private const val MASK_OKHTTP3_DOT = 1 shl 5
    private const val MASK_OKHTTP_BOM = 1 shl 6
    private const val MASK_SENTRY_ANDROID_INIT = 1 shl 7
    private const val MASK_SENTRY_INIT = 1 shl 8
    private const val MASK_CRASH_OUTBOX = 1 shl 9
    private const val MASK_CRASH_NON_FATAL = 1 shl 10
    private const val MASK_TELEMETRY_RING = 1 shl 11

    private val DEX_MAGIC = "dex\n".encodeToByteArray()
    private val ANCHOR_PHOENIX_PREFIX = "Phoenix didn't stay up for 3 launches".encodeToByteArray()

    private class AnchorRule(val text: ByteArray, val mask: Int)

    private val EXACT_ANCHORS = arrayOf(
        AnchorRule("Already Executed".encodeToByteArray(), MASK_ALREADY_EXECUTED),
        AnchorRule("Canceled".encodeToByteArray(), MASK_CANCELED),
        AnchorRule("OkHttp ".encodeToByteArray(), MASK_OKHTTP_PREFIX),
        AnchorRule("canceled due to ".encodeToByteArray(), MASK_CANCELED_DUE_TO),
        AnchorRule("okhttp3.".encodeToByteArray(), MASK_OKHTTP3_DOT),
        AnchorRule("0000ffff".encodeToByteArray(), MASK_OKHTTP_BOM),
        AnchorRule("Fatal error during SentryAndroid.init(...)".encodeToByteArray(), MASK_SENTRY_ANDROID_INIT),
        AnchorRule(
            "Sentry has been already initialized. Previous configuration will be overwritten.".encodeToByteArray(),
            MASK_SENTRY_INIT,
        ),
        AnchorRule("CrashReporter.outbox".encodeToByteArray(), MASK_CRASH_OUTBOX),
        AnchorRule("CrashReporter.setNonFatalTarget".encodeToByteArray(), MASK_CRASH_NON_FATAL),
        AnchorRule("TelemetryRing".encodeToByteArray(), MASK_TELEMETRY_RING),
    )

    private val DEX_ENTRY_REGEX = Regex("""^classes(\d*)\.dex$""")

    private val OP_LENGTH = IntArray(256) { 1 }.apply {
        val twoUnit = intArrayOf(
            0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29,
            0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
            0x3b, 0x3c, 0x3d, 0xfe, 0xff,
        )
        for (op in twoUnit) this[op] = 2
        for (op in 0x44..0x6d) this[op] = 2
        for (op in 0x90..0xaf) this[op] = 2
        for (op in 0xd0..0xe2) this[op] = 2

        val threeUnit = intArrayOf(
            0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c, 0xfc, 0xfd,
        )
        for (op in threeUnit) this[op] = 3
        for (op in 0x6e..0x72) this[op] = 3
        for (op in 0x74..0x78) this[op] = 3

        this[0x18] = 5
        this[0xfa] = 4
        this[0xfb] = 4
    }

    private fun Int.hasAll(bits: Int): Boolean = (this and bits) == bits

    fun resolveClass(descriptor: String, classLoader: ClassLoader): Class<*>? {
        return when (descriptor) {
            "Z" -> Boolean::class.javaPrimitiveType
            "B" -> Byte::class.javaPrimitiveType
            "S" -> Short::class.javaPrimitiveType
            "C" -> Char::class.javaPrimitiveType
            "I" -> Int::class.javaPrimitiveType
            "J" -> Long::class.javaPrimitiveType
            "F" -> Float::class.javaPrimitiveType
            "D" -> Double::class.javaPrimitiveType
            "V" -> Void.TYPE
            else -> runCatching {
                val name = when {
                    descriptor.startsWith("[") -> descriptor.replace('/', '.')
                    descriptor.startsWith("L") && descriptor.endsWith(";") ->
                        descriptor.substring(1, descriptor.length - 1).replace('/', '.')
                    else -> descriptor
                }
                Class.forName(name, false, classLoader)
            }.getOrNull()
        }
    }

    fun scanApk(apkFile: File): ScanResult = scanApks(listOf(apkFile))

    fun scanApks(apkFiles: List<File>): ScanResult {
        val state = Accumulator()
        for (file in apkFiles) {
            if (!file.isFile) continue
            runCatching {
                ZipFile(file).use { zip ->
                    val dexEntries = zip.entries().asSequence()
                        .mapNotNull { entry ->
                            val match = DEX_ENTRY_REGEX.matchEntire(entry.name) ?: return@mapNotNull null
                            val index = match.groupValues[1].toIntOrNull() ?: 1
                            index to entry
                        }
                        .sortedBy { it.first }
                        .toList()
                    for ((_, entry) in dexEntries) {
                        zip.getInputStream(entry).use { stream ->
                            scanDex(stream.readBytes(), state)
                        }
                    }
                }
            }
        }
        return state.finish()
    }

    private class Accumulator {
        var phoenixLauncher: MethodRef? = null
        val executeCandidates = mutableListOf<MethodRef>()
        val chainCandidates = mutableListOf<MethodRef>()
        var okHttpAsyncCallRun: MethodRef? = null
        var okHttpUtilClass: String? = null
        var sentryAndroidInit: MethodRef? = null
        var sentryInit: MethodRef? = null
        var crashReporterOutbox: MethodRef? = null
        var crashReporterSetNonFatal: MethodRef? = null
        val telemetryRingCandidates = mutableListOf<String>()

        fun record(ref: MethodRef, mask: Int) {
            if (mask.hasAll(MASK_PHOENIX_LAUNCH) &&
                ref.returnType == "Z" &&
                ref.methodName != "<clinit>"
            ) {
                phoenixLauncher = ref
            }
            if (mask.hasAll(MASK_ALREADY_EXECUTED) &&
                ref.parameterTypes.isEmpty() &&
                ref.returnType.startsWith("L")
            ) {
                executeCandidates.add(ref)
            }
            if (mask.hasAll(MASK_CANCELED) &&
                ref.parameterTypes.isEmpty() &&
                ref.returnType.startsWith("L")
            ) {
                chainCandidates.add(ref)
            }
            if (mask.hasAll(MASK_OKHTTP_PREFIX or MASK_CANCELED_DUE_TO) &&
                ref.methodName == "run" &&
                ref.parameterTypes.isEmpty() &&
                ref.returnType == "V"
            ) {
                okHttpAsyncCallRun = ref
            }
            if (mask.hasAll(MASK_OKHTTP3_DOT or MASK_OKHTTP_BOM) && ref.methodName == "<clinit>") {
                okHttpUtilClass = ref.className
            }
            if (mask.hasAll(MASK_SENTRY_ANDROID_INIT)) {
                sentryAndroidInit = ref
            }
            if (mask.hasAll(MASK_SENTRY_INIT)) {
                sentryInit = ref
            }
            if (mask.hasAll(MASK_CRASH_OUTBOX) && ref.returnType == "V") {
                crashReporterOutbox = ref
            }
            if (mask.hasAll(MASK_CRASH_NON_FATAL) && ref.returnType == "V") {
                crashReporterSetNonFatal = ref
            }
            if (mask.hasAll(MASK_TELEMETRY_RING) &&
                ref.methodName == "getName" &&
                ref.parameterTypes.isEmpty() &&
                ref.returnType == "Ljava/lang/String;"
            ) {
                telemetryRingCandidates.add(ref.className)
            }
        }

        fun finish(): ScanResult {
            val matchedPair = executeCandidates.firstNotNullOfOrNull { exec ->
                chainCandidates
                    .firstOrNull { chain -> exec.className == chain.className && exec.returnType == chain.returnType }
                    ?.let { chain -> exec to chain }
            }
            return ScanResult(
                phoenixLauncher = phoenixLauncher,
                okHttpRealCallExecute = matchedPair?.first,
                okHttpRealCallChain = matchedPair?.second,
                okHttpAsyncCallRun = okHttpAsyncCallRun,
                okHttpUtilClass = okHttpUtilClass,
                sentryAndroidInit = sentryAndroidInit,
                sentryInit = sentryInit,
                crashReporterOutbox = crashReporterOutbox,
                crashReporterSetNonFatal = crashReporterSetNonFatal,
                telemetryRingCandidates = telemetryRingCandidates,
            )
        }
    }

    private fun scanDex(data: ByteArray, acc: Accumulator) {
        if (data.size < 112 || !matchesAt(data, 0, DEX_MAGIC)) return

        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56)
        val stringIdsOff = buf.getInt(60)
        val typeIdsOff = buf.getInt(68)
        val protoIdsOff = buf.getInt(76)
        val methodIdsOff = buf.getInt(92)
        val classDefsSize = buf.getInt(96)
        val classDefsOff = buf.getInt(100)
        if (stringIdsSize <= 0 || classDefsSize <= 0) return

        val anchorMasks = buildAnchorMasks(data, buf, stringIdsSize, stringIdsOff)
        if (anchorMasks.none { it != 0 }) return

        val reader = DexReader(data, buf, stringIdsOff, typeIdsOff, protoIdsOff, methodIdsOff)

        for (i in 0 until classDefsSize) {
            val classDataOff = buf.getInt(classDefsOff + i * 32 + 24)
            if (classDataOff == 0) continue

            val cursor = Cursor(data, classDataOff)
            val staticFields = cursor.readUleb128()
            val instanceFields = cursor.readUleb128()
            val directMethods = cursor.readUleb128()
            val virtualMethods = cursor.readUleb128()

            repeat(staticFields + instanceFields) {
                cursor.readUleb128()
                cursor.readUleb128()
            }

            for (count in intArrayOf(directMethods, virtualMethods)) {
                var methodIdx = 0
                repeat(count) {
                    methodIdx += cursor.readUleb128()
                    cursor.readUleb128()
                    val codeOff = cursor.readUleb128()
                    if (codeOff == 0) return@repeat

                    val insnsSize = buf.getInt(codeOff + 12)
                    val mask = scanMethodStrings(buf, codeOff + 16, insnsSize, anchorMasks)
                    if (mask != 0) {
                        acc.record(reader.readMethodRef(methodIdx), mask)
                    }
                }
            }
        }
    }

    private fun buildAnchorMasks(
        data: ByteArray,
        buf: ByteBuffer,
        stringIdsSize: Int,
        stringIdsOff: Int,
    ): IntArray {
        val masks = IntArray(stringIdsSize)
        val cursor = Cursor(data, 0)
        for (i in 0 until stringIdsSize) {
            cursor.pos = buf.getInt(stringIdsOff + i * 4)
            cursor.readUleb128()
            val p = cursor.pos
            var end = p
            while (data[end] != 0.toByte()) {
                end++
            }
            val len = end - p
            var mask = 0
            if (len >= ANCHOR_PHOENIX_PREFIX.size && matchesAt(data, p, ANCHOR_PHOENIX_PREFIX)) {
                mask = mask or MASK_PHOENIX_LAUNCH
            }
            for (rule in EXACT_ANCHORS) {
                if (len == rule.text.size && matchesAt(data, p, rule.text)) {
                    mask = mask or rule.mask
                }
            }
            if (mask != 0) {
                masks[i] = mask
            }
        }
        return masks
    }

    private fun scanMethodStrings(
        buf: ByteBuffer,
        insnsStart: Int,
        insnsSize: Int,
        anchorMasks: IntArray,
    ): Int {
        var mask = 0
        var pos = 0
        val strCount = anchorMasks.size
        while (pos < insnsSize) {
            val unit = buf.getShort(insnsStart + pos * 2).toInt() and 0xFFFF
            when (unit) {
                0x0100 -> if (pos + 1 < insnsSize) {
                    val size = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xFFFF
                    pos += size * 2 + 4
                    continue
                }
                0x0200 -> if (pos + 1 < insnsSize) {
                    val size = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xFFFF
                    pos += size * 4 + 2
                    continue
                }
                0x0300 -> if (pos + 3 < insnsSize) {
                    val elemWidth = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xFFFF
                    val size = buf.getInt(insnsStart + (pos + 2) * 2)
                    pos += (size * elemWidth + 1) / 2 + 4
                    continue
                }
            }
            val op = unit and 0xFF
            when (op) {
                0x1a -> if (pos + 1 < insnsSize) {
                    val strIdx = buf.getShort(insnsStart + (pos + 1) * 2).toInt() and 0xFFFF
                    if (strIdx < strCount) mask = mask or anchorMasks[strIdx]
                }
                0x1b -> if (pos + 2 < insnsSize) {
                    val strIdx = buf.getInt(insnsStart + (pos + 1) * 2)
                    if (strIdx in 0 until strCount) mask = mask or anchorMasks[strIdx]
                }
            }
            pos += OP_LENGTH[op]
        }
        return mask
    }

    private fun matchesAt(data: ByteArray, offset: Int, pattern: ByteArray): Boolean {
        for (i in pattern.indices) {
            if (data[offset + i] != pattern[i]) return false
        }
        return true
    }

    private class Cursor(private val data: ByteArray, var pos: Int) {
        fun readUleb128(): Int {
            var result = 0
            var shift = 0
            while (true) {
                val b = data[pos++].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0) return result
                shift += 7
            }
        }
    }

    private class DexReader(
        private val data: ByteArray,
        private val buf: ByteBuffer,
        private val stringIdsOff: Int,
        private val typeIdsOff: Int,
        private val protoIdsOff: Int,
        private val methodIdsOff: Int,
    ) {
        fun readString(idx: Int): String {
            val cursor = Cursor(data, buf.getInt(stringIdsOff + idx * 4))
            val utf16Len = cursor.readUleb128()
            var p = cursor.pos
            val chars = CharArray(utf16Len)
            var out = 0
            while (out < utf16Len) {
                val a = data[p++].toInt() and 0xFF
                chars[out++] = when {
                    a == 0 -> break
                    a < 0x80 -> a.toChar()
                    (a and 0xE0) == 0xC0 -> {
                        val b = data[p++].toInt() and 0xFF
                        (((a and 0x1F) shl 6) or (b and 0x3F)).toChar()
                    }
                    (a and 0xF0) == 0xE0 -> {
                        val b = data[p++].toInt() and 0xFF
                        val c = data[p++].toInt() and 0xFF
                        (((a and 0x0F) shl 12) or ((b and 0x3F) shl 6) or (c and 0x3F)).toChar()
                    }
                    else -> break
                }
            }
            return String(chars, 0, out)
        }

        fun readType(typeIdx: Int): String = readString(buf.getInt(typeIdsOff + typeIdx * 4))

        fun readMethodRef(methodIdx: Int): MethodRef {
            val base = methodIdsOff + methodIdx * 8
            val classIdx = buf.getShort(base).toInt() and 0xFFFF
            val protoIdx = buf.getShort(base + 2).toInt() and 0xFFFF
            val nameIdx = buf.getInt(base + 4)

            val protoBase = protoIdsOff + protoIdx * 12
            val retTypeIdx = buf.getInt(protoBase + 4)
            val paramsOff = buf.getInt(protoBase + 8)
            val params = if (paramsOff == 0) {
                emptyList()
            } else {
                val count = buf.getInt(paramsOff)
                List(count) { j ->
                    readType(buf.getShort(paramsOff + 4 + j * 2).toInt() and 0xFFFF)
                }
            }
            return MethodRef(
                className = readType(classIdx),
                methodName = readString(nameIdx),
                parameterTypes = params,
                returnType = readType(retTypeIdx),
            )
        }
    }
}
