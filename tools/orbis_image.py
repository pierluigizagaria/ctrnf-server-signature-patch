"""Read file-backed virtual addresses from PS4 SELF and ELF executables."""
import struct

SELF_MAGIC = b"\x4f\x15\x3d\x1d"
PROGRAM_NAMES = {
    1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 7: "TLS",
    0x61000000: "SCE_DYNLIBDATA", 0x61000001: "SCE_PROCPARAM",
    0x61000002: "SCE_MODULE_PARAM", 0x61000010: "SCE_RELRO",
    0x6474e550: "GNU_EH_FRAME", 0x6fffff00: "SCE_COMMENT", 0x6fffff01: "SCE_LIBVERSION",
}


class OrbisImage:
    def __init__(self, data: bytes):
        self.data = data
        self.segments = []
        self.mappings = []
        self.is_self = data.startswith(SELF_MAGIC)
        elf_start = 0
        if self.is_self:
            self.slice(0, 32)
            if data[6] != 1:
                raise ValueError("Only little-endian SELF is supported")
            count = struct.unpack_from("<H", data, 24)[0]
            if not 0 < count <= 4096:
                raise ValueError("Unsupported SELF segment count")
            elf_start = 32 + 32 * count
            self.slice(32, 32 * count)
            for index in range(count):
                flags, offset, size, memory_size = struct.unpack_from("<4Q", data, 32 + 32 * index)
                self.slice(offset, size)
                self.segments.append({
                    "index": index, "flags": hex(flags), "program_index": (flags >> 20) & 0xfff,
                    "offset": offset, "size_bytes": size, "memory_size": memory_size,
                    "blocked": bool(flags & 0x800), "encrypted": bool(flags & 2), "compressed": bool(flags & 8),
                })
        elf = struct.unpack("<16sHHIQQQIHHHHHH", self.slice(elf_start, 64))
        ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phcount, shsize, shcount, shstr = elf
        if ident[:7] != b"\x7fELF\x02\x01\x01" or machine != 62 or version != 1 or ehsize != 64:
            raise ValueError("Expected ELF64 little-endian x86-64")
        if phsize != 56 or not 0 < phcount <= 4096:
            raise ValueError("Unsupported ELF program table")
        self.elf_header = {"container_offset": elf_start, "type": hex(kind), "machine": machine,
                           "osabi": ident[7], "entry_vaddr": entry, "program_count": phcount,
                           "section_count": shcount, "section_table_offset": shoff}
        self.programs = []
        for index in range(phcount):
            values = struct.unpack("<II6Q", self.slice(elf_start + phoff + index * phsize, phsize))
            p = dict(zip(("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"), values))
            if p["type"] in (1, 0x61000010) and p["filesz"] > p["memsz"]:
                raise ValueError("Loadable segment file size exceeds memory size")
            p.update(index=index, type_name=PROGRAM_NAMES.get(p["type"], hex(p["type"])))
            self.programs.append(p)
        if self.is_self:
            mapped_ids = set()
            for s in self.segments:
                if not s["blocked"]:
                    continue
                index = s["program_index"]
                if index >= phcount or index in mapped_ids:
                    raise ValueError("Invalid or duplicate SELF program mapping")
                mapped_ids.add(index)
                p = self.programs[index]
                if not s["encrypted"] and not s["compressed"]:
                    if s["size_bytes"] != p["filesz"]:
                        raise ValueError("SELF payload size differs from its ELF segment")
                    self.mappings.append((p["offset"], p["filesz"], s["offset"]))
        else:
            for p in self.programs:
                self.slice(p["offset"], p["filesz"])
            self.mappings.append((0, len(data), 0))

    def slice(self, start: int, size: int) -> bytes:
        if start < 0 or size < 0 or start + size > len(self.data):
            raise ValueError("Range extends beyond input")
        return self.data[start:start + size]

    def read(self, offset: int, size: int) -> bytes:
        if not size:
            return b""
        candidates = [(s, length, actual) for s, length, actual in self.mappings if s <= offset and offset + size <= s + length]
        if not candidates:
            raise ValueError(f"No readable payload for ELF range {offset:#x}+{size:#x}")
        results = [self.slice(actual + offset - start, size) for start, _, actual in candidates]
        if any(value != results[0] for value in results):
            raise ValueError("Conflicting ELF payload mappings")
        return results[0]

    def read_vaddr(self, address: int, size: int) -> bytes:
        candidates = [p for p in self.programs if p["type"] in (1, 0x61000010) and
                      p["vaddr"] <= address and address + size <= p["vaddr"] + p["filesz"]]
        if len(candidates) != 1:
            raise ValueError("Virtual address does not have a unique file-backed segment")
        p = candidates[0]
        return self.read(p["offset"] + address - p["vaddr"], size)
