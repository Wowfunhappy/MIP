#!/usr/bin/python
"""Mavericks port: stand-in for `gobjcopy -O binary`, which is not available
with the 10.9 toolchain.

Writes the bytes of every section of the payload dylib, laid out by virtual
address starting at the first section (__TEXT,__text), so that RIP/EIP-relative
references between code and data keep working once the blob is copied into
the target. Fails if the payload imports anything, has data outside __TEXT, or
does not start with _entry."""
import struct, sys

def main(src, dst):
    d = open(src, 'rb').read()
    magic = struct.unpack('<I', d[:4])[0]
    is64 = magic == 0xfeedfacf
    if magic not in (0xfeedface, 0xfeedfacf):
        sys.exit('%s: not a thin Mach-O file' % src)
    ncmds = struct.unpack('<I', d[16:20])[0]
    off = 32 if is64 else 28
    sections, symtab, undefined = [], None, 0
    for _ in range(ncmds):
        cmd, size = struct.unpack('<II', d[off:off + 8])
        if cmd in (0x19, 0x1):  # LC_SEGMENT_64 / LC_SEGMENT
            seg = d[off + 8:off + 24].rstrip(b'\0')
            nsects = struct.unpack('<I', d[off + (64 if is64 else 48):off + (68 if is64 else 52)])[0]
            p = off + (72 if is64 else 56)
            for _ in range(nsects):
                name = d[p:p + 16].rstrip(b'\0')
                segname = d[p + 16:p + 32].rstrip(b'\0')
                if is64:
                    addr, sz, foff = struct.unpack('<QQI', d[p + 32:p + 52])
                    p += 80
                else:
                    addr, sz, foff = struct.unpack('<III', d[p + 32:p + 44])
                    p += 68
                if sz:
                    sections.append((addr, sz, foff, segname, name))
        elif cmd == 0x2:  # LC_SYMTAB
            symtab = struct.unpack('<IIII', d[off + 8:off + 24])
        elif cmd == 0xb:  # LC_DYSYMTAB
            undefined = struct.unpack('<I', d[off + 8 + 4 * 5:off + 8 + 4 * 6])[0]
        off += size
    if undefined:
        sys.exit('%s: payload must not import symbols (%d undefined)' % (src, undefined))
    for s in sections:
        if s[3] != b'__TEXT':
            sys.exit('%s: unexpected section %s,%s outside __TEXT' % (src, s[3], s[4]))
    sections.sort()
    base = sections[0][0]
    # _entry must be the first thing in the blob: the injector jumps to its start.
    symoff, nsyms, stroff, _ = symtab
    entsize = 16 if is64 else 12
    entry = None
    for i in range(nsyms):
        e = d[symoff + i * entsize:symoff + (i + 1) * entsize]
        strx = struct.unpack('<I', e[:4])[0]
        value = struct.unpack('<Q' if is64 else '<I', e[8:16] if is64 else e[8:12])[0]
        name = d[stroff + strx:d.index(b'\0', stroff + strx)]
        if name == b'_entry':
            entry = value
    if entry != base:
        sys.exit('%s: _entry is at 0x%x, expected start of __text 0x%x' % (src, entry or 0, base))
    end = max(a + s for a, s, _, _, _ in sections)
    out = bytearray(end - base)
    for addr, sz, foff, _, _ in sections:
        out[addr - base:addr - base + sz] = d[foff:foff + sz]
    open(dst, 'wb').write(bytes(out))

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
