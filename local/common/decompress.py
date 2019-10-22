# coding:utf-8
# Use for HTTPResponse stream decompress.

import zlib
from _compression import DecompressReader
from io import DEFAULT_BUFFER_SIZE, RawIOBase, BufferedReader
from gzip import _PaddedFile, _GzipReader

try:
    from brotli import _brotli
    ffi = _brotli.ffi
    lib = _brotli.lib
except:
    _brotli = None

class DeflateReader(BufferedReader):
    def __init__(self, fileobj):
        self.fp = fileobj
        BufferedReader.__init__(self, _DeflateReader(fileobj))

    def __getattr__(self, name):
        return getattr(self.fp, name)

class _DeflateReader(DecompressReader):
    def __init__(self, fp):
        self.fp = fp
        CMF, FLG = magic = fp.read(2)
        # This is a compatible, some streams has no magic.
        if CMF & 0x0F != 8 or \
           CMF & 0x80 != 0 or \
           ((CMF << 8) + FLG) % 31 > 0:
            fp = _PaddedFile(fp, magic)
        DecompressReader.__init__(self,
                                  fp,
                                  zlib.decompressobj,
                                  wbits=-zlib.MAX_WBITS)
        self._buffer = None
        self._length = 0
        self._read = 0

    def read(self, size=-1):
        if size < 0:
            return self.readall()
        if not size or self._eof:
            return b''

        while True:
            if self._buffer:
                if self._read + size < self._length:
                    read = self._read
                    self._read += size
                    uncompress = self._buffer[read:self._read].tobytes()
                else:
                    uncompress = self._buffer[self._read:].tobytes()
                    self._buffer = None
                    self._read = 0
                break

            if self._decompressor.eof:
                # No stream will be appended. If stream has a magic,
                # in little probability a few bytes will be remained.
                self.fp.read()
                self._eof = True
                return b''

            buf = self._fp.read(DEFAULT_BUFFER_SIZE)
            uncompress = self._decompressor.decompress(buf, size)
            if self._decompressor.unconsumed_tail:
                self._buffer = memoryview(self._decompressor.flush())
                self._length = len(self._buffer)
            if uncompress != b'':
                break
            if buf == b'':
                raise EOFError('Compressed file ended before the '
                               'end-of-stream marker was reached')

        self._pos += len(uncompress)
        return uncompress

class GzipSock:
    def __init__(self, fileobj):
        self.fileobj = fileobj

    def makefile(self, mode):
        return BufferedReader(_GzipReader(self.fileobj))

class GzipReader(BufferedReader):
    def __init__(self, fileobj):
        self.fp = fileobj
        BufferedReader.__init__(self, _GzipReader(fileobj))

    def __getattr__(self, name):
        return getattr(self.fp, name)

class BrotliReader(RawIOBase):
    # A wrapper for brotlipy.
    # This code does not require class Inheritance of BufferedReader.
    # https://github.com/python-hyper/brotlipy
    def __init__(self, fileobj):
        self.fp = fileobj
        self.decompressor = BrotliDecompressor(fileobj)
        self.decompressor.send(None)
        self._buffer = None
        self._length = 0
        self._read = 0

    def __getattr__(self, name):
        return getattr(self.fp, name)

    def read(self, size=-1):
        if self.decompressor is None or size == 0:
            return b''

        if size > 0:
            b = bytearray(size)
            n = self.readinto(b)
            return memoryview(b)[:n].tobytes()
        else:
            return self.readall()
    read1 = read

    def readinto(self, b):
        size = len(b)
        if self.decompressor is None or size == 0:
            return 0

        read = 0
        if self._buffer:
            if self._read + size < self._length:
                read = self._read
                self._read += size
                b[:] = self._buffer[read:self._read]
                return size
            else:
                read = self._length - self._read
                b[:read] = self._buffer[self._read:]
                self._buffer = None
                self._read = 0

        rsize = max(size // 5, 1024)
        while True:
            try:
                data = self.decompressor.send(rsize)
            except StopIteration:
                self.decompressor = None
                break
            dsize = len(data)
            if read + dsize > size:
                self._buffer = memoryview(data)
                self._length = dsize
                self._read = size - read
                b[read:] = self._buffer[:self._read]
                return size
            else:
                _read = read
                read += dsize
                b[_read:read] = data
        return read

    def close(self):
        if self.decompressor:
            self.decompressor.close()
            self.decompressor = None
        self.fp.close()
        return RawIOBase.close(self)

class BrotliError(Exception):
    pass

def BrotliDecompressor(fileobj):
    # Almost copy from brotlipy's brotli.brotli.Decompressor class.
    dec = lib.BrotliDecoderCreateInstance(ffi.NULL, ffi.NULL, ffi.NULL)
    decoder = ffi.gc(dec, lib.BrotliDecoderDestroyInstance)
    need_input = True
    size = yield

    while True:
        if need_input:
            if size > 0:
                data = fileobj.read(size)
            else:
                data = fileobj.read()
            if not data:
                raise BrotliError('Decompression error: '
                                  'incomplete compressed stream')
            available_in = ffi.new('size_t *', len(data))
            in_buffer = ffi.new('uint8_t[]', data)
            next_in = ffi.new('uint8_t **', in_buffer)
            need_input = False

        buffer_size = 5 * len(data)
        available_out = ffi.new('size_t *', buffer_size)
        out_buffer = ffi.new('uint8_t[]', buffer_size)
        next_out = ffi.new('uint8_t **', out_buffer)

        rc = lib.BrotliDecoderDecompressStream(decoder,
                                               available_in,
                                               next_in,
                                               available_out,
                                               next_out,
                                               ffi.NULL)

        if rc == lib.BROTLI_DECODER_RESULT_ERROR:
            error_code = lib.BrotliDecoderGetErrorCode(decoder)
            error_message = lib.BrotliDecoderErrorString(error_code)
            raise BrotliError('Decompression error: %s'
                              % ffi.string(error_message))

        result = buffer_size - available_out[0]
        if result:
            size = yield ffi.buffer(out_buffer, result)[:]
        if rc == lib.BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
            assert available_in[0] == 0
            need_input = True
        elif rc == lib.BROTLI_DECODER_RESULT_SUCCESS:
            break
        else:
            assert rc == lib.BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT

decompress_readers = {
    'gzip': GzipReader,
    'deflate': DeflateReader
    }
if _brotli:
    decompress_readers['br'] = BrotliReader
