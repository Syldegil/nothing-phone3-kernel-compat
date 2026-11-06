"""Small read-only ELF64 LE parser for host audits (no loading or rewriting)."""
import struct

class ELF:
    def __init__(self, data):
        self.data = data
        if data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
            raise ValueError('Expected ELF64 LE AArch64')
        off = struct.unpack_from('<Q', data, 40)[0]
        size, count, index = struct.unpack_from('<HHH', data, 58)
        if size < 64 or not 0 < index < count or off + size * count > len(data):
            raise ValueError('Invalid section table')
        self.headers = [struct.unpack_from('<IIQQQQIIQQ', data, off + i * size) for i in range(count)]
        names = self.content(self.headers[index])
        self.sections = {self.string(names, h[0]): h for h in self.headers}

    @staticmethod
    def string(data, offset):
        end = data.find(b'\0', offset)
        if offset >= len(data) or end < 0:
            raise ValueError('Invalid string offset')
        return data[offset:end].decode('utf-8', 'strict')

    def content(self, header):
        if header[1] == 8:
            return b''
        off, size = header[4:6]
        if off + size > len(self.data):
            raise ValueError('Section out of bounds')
        return self.data[off:off+size]

    def section(self, name):
        return self.content(self.sections[name]) if name in self.sections else b''

    def symbols(self):
        for h in self.headers:
            if h[1] != 2:
                continue
            if h[9] != 24 or h[5] % 24:
                raise ValueError('Malformed symbol table')
            strings = self.content(self.headers[h[6]])
            for name, info, other, section, value, size in struct.iter_unpack('<IBBHQQ', self.content(h)):
                yield {'name': self.string(strings, name), 'binding': info >> 4,
                       'section': section, 'value': value, 'size': size}

    def exports(self):
        result = {}
        for s in self.symbols():
            if not s['name'].startswith('__crc_'):
                continue
            if not 0 < s['section'] < len(self.headers):
                raise ValueError('Unexpected CRC symbol section')
            h = self.headers[s['section']]
            if s['value'] + 4 > h[5]:
                raise ValueError('CRC offset out of bounds')
            result[s['name'][6:]] = struct.unpack_from('<I', self.data, h[4] + s['value'])[0]
        return result

    def versions(self):
        data = self.section('__versions')
        if len(data) % 64:
            raise ValueError('Malformed versions section')
        result = {}
        for off in range(0, len(data), 64):
            name = self.string(data[off+8:off+64], 0)
            if name in result:
                raise ValueError('Duplicate version record')
            result[name] = struct.unpack_from('<Q', data, off)[0]
        return result
