#include <android/log.h>
#include <link.h>

#include <algorithm>
#include <atomic>
#include <mutex>
#include <string_view>

#include "access_scanner.h"

namespace {

constexpr const char *kLogTag = "HelloPhoenix";
constexpr std::string_view kHostLibrary = "liblibdiscord_wasm_host.so";

using HookFunType = int (*)(void *func, void *replace, void **backup);
using UnhookFunType = int (*)(void *func);
using NativeOnModuleLoaded = void (*)(const char *name, void *handle);

struct NativeAPIEntries {
    uint32_t version;
    HookFunType hookFunc;
    UnhookFunType unhookFunc;
};

HookFunType g_hook_func = nullptr;
std::atomic<bool> g_patched{false};
std::mutex g_patch_mutex;

// Phoenix's Rust evaluator returns Option<bool> in the low byte: 1 = Some(true).
uint8_t always_allow_phoenix(void *) {
    return 1;
}

struct PhdrSearch {
    hellophoenix::MappedImage image;
    bool found = false;
};

int collect_host_phdr(struct dl_phdr_info *info, size_t, void *data) {
    if (!info->dlpi_name || !std::string_view(info->dlpi_name).ends_with(kHostLibrary)) {
        return 0;
    }
    auto *search = static_cast<PhdrSearch *>(data);
    search->found = true;
    uintptr_t bias = static_cast<uintptr_t>(info->dlpi_addr);
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info->dlpi_phdr[i];
        switch (ph.p_type) {
            case PT_LOAD:
                if ((ph.p_flags & PF_R) != 0) {
                    size_t mapped_len = static_cast<size_t>(std::min(ph.p_filesz, ph.p_memsz));
                    if (mapped_len == 0) break;
                    uintptr_t addr = bias + static_cast<uintptr_t>(ph.p_vaddr);
                    search->image.segments.push_back(hellophoenix::Segment{
                        .addr = addr,
                        .bytes = reinterpret_cast<const uint8_t *>(addr),
                        .size = mapped_len,
                        .executable = (ph.p_flags & PF_X) != 0,
                    });
                }
                break;
            case PT_GNU_EH_FRAME:
                search->image.eh_frame_hdr = bias + static_cast<uintptr_t>(ph.p_vaddr);
                break;
            case 0x70000001u:
                search->image.arm_exidx = bias + static_cast<uintptr_t>(ph.p_vaddr);
                search->image.arm_exidx_len = static_cast<size_t>(ph.p_memsz);
                break;
        }
    }
    return 1;
}

void try_patch_host() {
    if (g_patched.load(std::memory_order_acquire) || !g_hook_func) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_patch_mutex);
    if (g_patched.load(std::memory_order_relaxed)) {
        return;
    }

    PhdrSearch search;
    dl_iterate_phdr(&collect_host_phdr, &search);
    if (!search.found) {
        return;
    }

    hellophoenix::ScanDiagnostic diag;
    uintptr_t target =
        hellophoenix::find_access_evaluator(search.image, hellophoenix::host_arch(), &diag);
    if (target == 0) {
        __android_log_print(
            ANDROID_LOG_WARN,
            kLogTag,
            "Access evaluator not uniquely found (strings=%zu, slots=%zu, fns=%zu)",
            diag.string_hits,
            diag.slot_hits,
            diag.function_hits
        );
        return;
    }

    void *backup = nullptr;
    int rc = g_hook_func(
        reinterpret_cast<void *>(target),
        reinterpret_cast<void *>(&always_allow_phoenix),
        &backup
    );
    if (rc == 0) {
        g_patched.store(true, std::memory_order_release);
        __android_log_print(
            ANDROID_LOG_INFO,
            kLogTag,
            "Hooked Phoenix access evaluator at 0x%zx",
            static_cast<size_t>(target)
        );
    } else {
        __android_log_print(
            ANDROID_LOG_ERROR,
            kLogTag,
            "Failed to hook Phoenix access evaluator at 0x%zx (rc=%d)",
            static_cast<size_t>(target),
            rc
        );
    }
}

// Vector holds its module registry mutex during this callback, so never call dlopen here.
void on_library_loaded(const char *name, void *) {
    if (g_patched.load(std::memory_order_acquire)) {
        return;
    }
    if (!name || !std::string_view(name).ends_with(kHostLibrary)) {
        return;
    }
    try_patch_host();
}

}  // namespace

extern "C" __attribute__((visibility("default"))) NativeOnModuleLoaded native_init(
    const NativeAPIEntries *entries
) {
    if (!entries || !entries->hookFunc) {
        __android_log_print(ANDROID_LOG_ERROR, kLogTag, "Missing Vector native hook API");
        return nullptr;
    }
    g_hook_func = entries->hookFunc;
    try_patch_host();
    return &on_library_loaded;
}
