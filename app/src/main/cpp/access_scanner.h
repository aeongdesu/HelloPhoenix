#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace hellophoenix {

enum class Arch {
    Aarch64,
    Arm32,
    X86_64,
};

constexpr Arch host_arch() {
#if defined(__aarch64__)
    return Arch::Aarch64;
#elif defined(__arm__)
    return Arch::Arm32;
#elif defined(__x86_64__)
    return Arch::X86_64;
#else
#error "Unsupported target architecture"
#endif
}

struct Segment {
    uintptr_t addr = 0;
    const uint8_t *bytes = nullptr;
    size_t size = 0;
    bool executable = false;
};

template <typename T>
inline T read_unaligned(const uint8_t *p) {
    T val{};
    std::memcpy(&val, p, sizeof(T));
    return val;
}

struct MappedImage {
    std::vector<Segment> segments;
    uintptr_t eh_frame_hdr = 0;
    uintptr_t arm_exidx = 0;
    size_t arm_exidx_len = 0;
    size_t pointer_width = sizeof(uintptr_t);

    const uint8_t *read_bytes(uintptr_t addr, size_t len) const {
        for (const Segment &seg : segments) {
            if (addr >= seg.addr) {
                size_t offset = static_cast<size_t>(addr - seg.addr);
                if (offset <= seg.size && len <= seg.size - offset) {
                    return seg.bytes + offset;
                }
            }
        }
        return nullptr;
    }

    bool read_u32(uintptr_t addr, uint32_t &out) const {
        const uint8_t *p = read_bytes(addr, sizeof(out));
        if (!p) return false;
        out = read_unaligned<uint32_t>(p);
        return true;
    }

    bool read_i32(uintptr_t addr, int32_t &out) const {
        const uint8_t *p = read_bytes(addr, sizeof(out));
        if (!p) return false;
        out = read_unaligned<int32_t>(p);
        return true;
    }
};

struct ScanDiagnostic {
    size_t string_hits = 0;
    size_t slot_hits = 0;
    size_t function_hits = 0;
};

namespace detail {

template <typename EntryStart>
inline uintptr_t find_enclosing_function(size_t count, uintptr_t addr, EntryStart entry_start) {
    size_t lo = 0;
    size_t hi = count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        uintptr_t start = entry_start(mid);
        if (start == 0) return 0;
        if (start <= addr) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo == 0 ? 0 : entry_start(lo - 1u);
}

inline bool eh_frame_table(const MappedImage &img, uint32_t &count_out) {
    if (img.eh_frame_hdr == 0) return false;
    const uint8_t *hdr = img.read_bytes(img.eh_frame_hdr, 12);
    if (!hdr) return false;
    uint8_t frame_enc = static_cast<uint8_t>(hdr[1] & 0x0Fu);
    if (hdr[0] != 1 || (frame_enc != 0x03u && frame_enc != 0x0Bu)) return false;
    if ((hdr[2] != 0x03u && hdr[2] != 0x0Bu) || hdr[3] != 0x3Bu) return false;
    int32_t raw_count = read_unaligned<int32_t>(hdr + 8);
    if (raw_count <= 0) return false;
    count_out = static_cast<uint32_t>(raw_count);
    return true;
}

inline uintptr_t eh_frame_entry_start(const MappedImage &img, size_t index) {
    int32_t rel = 0;
    uintptr_t entry = img.eh_frame_hdr + 12 + static_cast<uintptr_t>(index) * 8u;
    if (!img.read_i32(entry, rel)) return 0;
    return static_cast<uintptr_t>(static_cast<intptr_t>(img.eh_frame_hdr) + rel);
}

inline uintptr_t eh_frame_first_pc(const MappedImage &img) {
    uint32_t count = 0;
    if (!eh_frame_table(img, count)) return 0;
    return eh_frame_entry_start(img, 0);
}

inline uintptr_t eh_frame_function_start(const MappedImage &img, uintptr_t addr) {
    uint32_t count = 0;
    if (!eh_frame_table(img, count)) return 0;
    return find_enclosing_function(count, addr, [&](size_t idx) {
        return eh_frame_entry_start(img, idx);
    });
}

inline uintptr_t arm_exidx_entry_start(const MappedImage &img, size_t index) {
    uintptr_t at = img.arm_exidx + index * 8u;
    uint32_t raw = 0;
    if (!img.read_u32(at, raw)) return 0;
    int32_t prel31 = static_cast<int32_t>(raw << 1u) >> 1;
    return static_cast<uintptr_t>(static_cast<intptr_t>(at) + prel31);
}

inline uintptr_t arm_exidx_function_start(const MappedImage &img, uintptr_t addr) {
    if (img.arm_exidx == 0 || img.arm_exidx_len < 8u) return 0;
    return find_enclosing_function(img.arm_exidx_len / 8u, addr, [&](size_t idx) {
        return arm_exidx_entry_start(img, idx);
    });
}

inline bool contains_addr(const std::vector<uintptr_t> &addrs, uintptr_t needle) {
    return std::find(addrs.begin(), addrs.end(), needle) != addrs.end();
}

inline std::vector<uintptr_t> find_bytes(const MappedImage &img, std::string_view needle) {
    std::vector<uintptr_t> hits;
    if (needle.empty()) return hits;
    for (const Segment &seg : img.segments) {
        const uint8_t *cur = seg.bytes;
        const uint8_t *end = seg.bytes + seg.size;
        while (cur < end) {
            const uint8_t *match = std::search(cur, end, needle.begin(), needle.end());
            if (match == end) break;
            hits.push_back(seg.addr + static_cast<size_t>(match - seg.bytes));
            cur = match + 1;
        }
    }
    return hits;
}

inline bool is_ascii_digit(uint8_t b) {
    return b >= '0' && b <= '9';
}

inline bool is_year_month(const uint8_t *p) {
    return is_ascii_digit(p[0]) && is_ascii_digit(p[1]) &&
           is_ascii_digit(p[2]) && is_ascii_digit(p[3]) &&
           p[4] == '-' && is_ascii_digit(p[5]) && is_ascii_digit(p[6]);
}

inline std::vector<uintptr_t> find_dated_experiment_strings(const MappedImage &img) {
    constexpr std::string_view kSuffix = "-phoenix-app-access";
    std::vector<uintptr_t> hits;
    for (const Segment &seg : img.segments) {
        const uint8_t *cur = seg.bytes;
        const uint8_t *end = seg.bytes + seg.size;
        while (cur < end) {
            const uint8_t *match = std::search(cur, end, kSuffix.begin(), kSuffix.end());
            if (match == end) break;
            size_t off = static_cast<size_t>(match - seg.bytes);
            if (off >= 7 && is_year_month(match - 7)) {
                hits.push_back(seg.addr + off - 7);
            }
            cur = match + 1;
        }
    }
    return hits;
}

// Rust stores &str as { const uint8_t *ptr, usize len } in non-executable rodata/relro.
inline std::vector<uintptr_t> find_str_slots(
    const MappedImage &img,
    const std::vector<uintptr_t> &str_addrs,
    size_t str_len
) {
    std::vector<uintptr_t> slots;
    if (str_addrs.empty()) return slots;
    const size_t width = img.pointer_width;
    for (const Segment &seg : img.segments) {
        if (seg.executable) continue;
        size_t rem = seg.addr % width;
        size_t off = (rem == 0) ? 0 : (width - rem);
        while (off + 2 * width <= seg.size) {
            uint64_t ptr_val = 0;
            uint64_t len_val = 0;
            std::memcpy(&ptr_val, seg.bytes + off, width);
            std::memcpy(&len_val, seg.bytes + off + width, width);
            if (len_val == str_len && contains_addr(str_addrs, static_cast<uintptr_t>(ptr_val))) {
                slots.push_back(seg.addr + off);
            }
            off += width;
        }
    }
    return slots;
}

inline size_t code_start_offset(const Segment &seg, uintptr_t first_pc) {
    if (first_pc > seg.addr && first_pc < seg.addr + seg.size) {
        return static_cast<size_t>(first_pc - seg.addr);
    }
    return 0;
}

inline void scan_aarch64(
    const MappedImage &img,
    const std::vector<uintptr_t> &slots,
    std::vector<uintptr_t> &functions
) {
    std::vector<uintptr_t> slot_pages;
    slot_pages.reserve(slots.size());
    for (uintptr_t slot : slots) {
        slot_pages.push_back(slot & ~uintptr_t{0xFFFu});
    }

    uintptr_t first_pc = eh_frame_first_pc(img);
    for (const Segment &seg : img.segments) {
        if (!seg.executable) continue;
        size_t off = code_start_offset(seg, first_pc);
        size_t misalign = (seg.addr + off) & 3u;
        if (misalign != 0) off += (4u - misalign);

        while (off + 4u <= seg.size) {
            uint32_t w = read_unaligned<uint32_t>(seg.bytes + off);
            if ((w & 0x9F000000u) == 0x90000000u) {
                int64_t imm = static_cast<int64_t>(((w >> 29u) & 3u) | (((w >> 5u) & 0x7FFFFu) << 2u));
                if (imm & (1LL << 20)) imm -= (1LL << 21);
                uintptr_t pc = seg.addr + off;
                uintptr_t page = static_cast<uintptr_t>(static_cast<int64_t>(pc & ~uintptr_t{0xFFFu}) + (imm << 12));
                if (contains_addr(slot_pages, page)) {
                    uint32_t rd = w & 0x1Fu;
                    for (size_t j = 1; j <= 4 && off + j * 4u + 4u <= seg.size; ++j) {
                        uint32_t nw = read_unaligned<uint32_t>(seg.bytes + off + j * 4u);
                        if (((nw >> 5u) & 0x1Fu) != rd) continue;
                        uint32_t imm12 = (nw >> 10u) & 0xFFFu;
                        uint32_t op = nw & 0xFFC00000u;
                        uintptr_t target = 0;
                        if (op == 0x91000000u) {
                            target = page + imm12;
                        } else if (op == 0xF9400000u) {
                            target = page + static_cast<uintptr_t>(imm12) * 8u;
                        }
                        if (target != 0 && contains_addr(slots, target)) {
                            uintptr_t fn = eh_frame_function_start(img, pc);
                            if (fn != 0) functions.push_back(fn);
                        }
                    }
                }
            }
            off += 4u;
        }
    }
}

inline void scan_x86_64(
    const MappedImage &img,
    const std::vector<uintptr_t> &slots,
    std::vector<uintptr_t> &functions
) {
    uintptr_t first_pc = eh_frame_first_pc(img);
    for (const Segment &seg : img.segments) {
        if (!seg.executable) continue;
        size_t off = code_start_offset(seg, first_pc);
        while (off + 7u <= seg.size) {
            uint8_t rex = seg.bytes[off];
            uint8_t op = seg.bytes[off + 1];
            uint8_t modrm = seg.bytes[off + 2];
            if ((rex == 0x48u || rex == 0x4Cu) &&
                (op == 0x8Bu || op == 0x8Du) &&
                (modrm & 0xC7u) == 0x05u) {
                int32_t disp = read_unaligned<int32_t>(seg.bytes + off + 3);
                uintptr_t pc = seg.addr + off;
                uintptr_t target = static_cast<uintptr_t>(static_cast<intptr_t>(pc + 7u) + disp);
                if (contains_addr(slots, target)) {
                    uintptr_t fn = eh_frame_function_start(img, pc);
                    if (fn != 0) functions.push_back(fn);
                }
            }
            ++off;
        }
    }
}

// Thumb-2 loads pc-relative offsets from a literal pool into Rn before `add Rn, pc`.
inline void scan_arm32(
    const MappedImage &img,
    const std::vector<uintptr_t> &slots,
    std::vector<uintptr_t> &functions
) {
    uintptr_t first_pc = (img.arm_exidx != 0 && img.arm_exidx_len >= 8u)
        ? arm_exidx_entry_start(img, 0)
        : 0;
    for (const Segment &seg : img.segments) {
        if (!seg.executable) continue;
        size_t off = code_start_offset(seg, first_pc);
        if (((seg.addr + off) & 1u) != 0) ++off;

        int32_t loaded[16]{};
        bool has_loaded[16]{};
        while (off + 2u <= seg.size) {
            uint16_t first = read_unaligned<uint16_t>(seg.bytes + off);
            uintptr_t pool = (seg.addr + off + 4u) & ~uintptr_t{3u};
            uint16_t top5 = static_cast<uint16_t>(first >> 11u);
            if (top5 >= 0x1Du && top5 <= 0x1Fu) {
                if ((first & 0xFF7Fu) == 0xF85Fu && off + 4u <= seg.size) {
                    uint16_t second = read_unaligned<uint16_t>(seg.bytes + off + 2u);
                    uintptr_t imm = static_cast<uintptr_t>(second & 0xFFFu);
                    uintptr_t literal = ((first & 0x80u) == 0) ? (pool - imm) : (pool + imm);
                    uint32_t reg = static_cast<uint32_t>(second >> 12u);
                    has_loaded[reg] = img.read_i32(literal, loaded[reg]);
                }
                off += 4u;
                continue;
            }
            if ((first & 0xF800u) == 0x4800u) {
                uint32_t reg = static_cast<uint32_t>((first >> 8u) & 7u);
                uintptr_t literal = pool + static_cast<uintptr_t>(first & 0xFFu) * 4u;
                has_loaded[reg] = img.read_i32(literal, loaded[reg]);
            } else if ((first & 0xFF78u) == 0x4478u) {
                uint32_t rn = static_cast<uint32_t>((((first >> 7u) & 1u) << 3u) | (first & 7u));
                if (has_loaded[rn]) {
                    uintptr_t pc = seg.addr + off + 4u;
                    uintptr_t target = static_cast<uintptr_t>(static_cast<intptr_t>(pc) + loaded[rn]);
                    if (contains_addr(slots, target)) {
                        uintptr_t fn = arm_exidx_function_start(img, seg.addr + off);
                        if (fn != 0) functions.push_back(fn);
                    }
                }
            }
            off += 2u;
        }
    }
}

inline uintptr_t resolve_for_strings(
    const MappedImage &img,
    Arch arch,
    const std::vector<uintptr_t> &str_addrs,
    size_t str_len,
    ScanDiagnostic *diag
) {
    std::vector<uintptr_t> slots = find_str_slots(img, str_addrs, str_len);
    std::vector<uintptr_t> functions;
    if (!slots.empty()) {
        switch (arch) {
            case Arch::Aarch64:
                scan_aarch64(img, slots, functions);
                break;
            case Arch::X86_64:
                scan_x86_64(img, slots, functions);
                break;
            case Arch::Arm32:
                scan_arm32(img, slots, functions);
                break;
        }
        std::sort(functions.begin(), functions.end());
        functions.erase(std::unique(functions.begin(), functions.end()), functions.end());
    }
    if (diag) {
        diag->string_hits = str_addrs.size();
        diag->slot_hits = slots.size();
        diag->function_hits = functions.size();
    }
    if (functions.size() != 1) return 0;
    return arch == Arch::Arm32 ? (functions[0] | uintptr_t{1u}) : functions[0];
}

}  // namespace detail

inline uintptr_t find_access_evaluator(
    const MappedImage &img,
    Arch arch,
    ScanDiagnostic *diag = nullptr
) {
    constexpr std::string_view kExperiment = "2026-11-phoenix-app-access";
    std::vector<uintptr_t> str_addrs = detail::find_bytes(img, kExperiment);
    if (!str_addrs.empty()) {
        uintptr_t hit = detail::resolve_for_strings(img, arch, str_addrs, kExperiment.size(), diag);
        if (hit != 0) return hit;
    }

    std::vector<uintptr_t> dated = detail::find_dated_experiment_strings(img);
    if (!dated.empty()) {
        return detail::resolve_for_strings(img, arch, dated, kExperiment.size(), diag);
    }
    if (diag) *diag = ScanDiagnostic{};
    return 0;
}

}  // namespace hellophoenix
