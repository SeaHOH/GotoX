# coding:utf-8

import zlib
from _compression import DecompressReader
from io import DEFAULT_BUFFER_SIZE, BufferedReader
from gzip import _PaddedFile, _GzipReader
from brotli._brotli import ffi, lib

class DeflateReader(BufferedReader):
    def __init__(self, fileobj):
        self.fp = fileobj
        BufferedReader.__init__(self, _DeflateReader(fileobj))

    def __getattr__(self, attr):
        return getattr(self.fp, attr)

class _DeflateReader(DecompressReader):
    def __init__(self, fp):
        magic = fp.read(2)
        if magic != b'\170\234':
            fp = _PaddedFile(fp, magic)
        super().__init__(fp, zlib.decompressobj, wbits=-zlib.MAX_WBITS)
        self._length = 0
        self._read = 0

    def read(self, size=-1):
        if size < 0:
            return self.readall()
        if not size or self._eof:
            return b''

        while True:
            if self._decompressor.eof:
                return b''

            if self._decompressor.unconsumed_tail:
                if self._read + size < self._length:
                    read = self._read
                    self._read += size
                    uncompress = self._decompressor.unconsumed_tail[read:self._read]
                else:
                    uncompress = self._decompressor.unconsumed_tail[self._read:]
                    self._read = 0
                    self._decompressor.flush()
                break

            buf = self._fp.read(DEFAULT_BUFFER_SIZE)
            uncompress = self._decompressor.decompress(buf, size)
            if self._decompressor.unconsumed_tail:
                self._length = len(self._decompressor.unconsumed_tail)
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

    def __getattr__(self, attr):
        return getattr(self.fp, attr)

class BrotliReader:
    # IOReader-like object wrapper for brotlipy decompress
    # https://github.com/python-hyper/brotlipy
    def __init__(self, fileobj):
        self.fp = fileobj
        self.decompressor = BrotliDecompressor(fileobj)
        self.decompressor.send(None)
        self.tmpdata = None

    def __getattr__(self, attr):
        return getattr(self.fp, attr)

    def read(self, size=-1):
        if self.decompressor is None or size == 0:
            return b''

        if size > 0:
            b = bytearray(size)
            n = self.readinto(b)
            return memoryview(b)[:n].tobytes()
        else:
            chunks =[]
            while True:
                try:
                    data = self.decompressor.send(32768) #32KB
                except StopIteration:
                    self.decompressor = None
                    break
                chunks.append(data)
            return b''.join(chunks)
    read1 = read

    def readinto(self, b):
        bsize = len(b)
        if self.decompressor is None or bsize == 0:
            return 0

        l = 0
        data = self.tmpdata
        if data:
            dsize = len(data)
            p = self.p
            l += dsize - p
            if l > bsize:
                self.p += bsize
                b[:] = data[p:self.p]
                return bsize
            else:
                b[:l] = data[p:]
                self.tmpdata = None

        size = max(bsize // 5, 1)
        while True:
            try:
                data = self.decompressor.send(size)
            except StopIteration:
                self.decompressor = None
                break
            data = memoryview(data)
            dsize = len(data)
            e = l + dsize
            if e > bsize:
                self.tmpdata = data
                self.p = p = dsize + bsize - e
                b[l:] = data[:p]
                return bsize
            else:
                b[l:e] = data #data[:]
                l = e
        return l

    def close(self):
        if self.decompressor:
            self.decompressor.close()
            self.decompressor = None
        self.fp.close()

class BrotliError(Exception):
    pass

def BrotliDecompressor(fileobj):
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
                raise BrotliError('Decompression error: incomplete compressed stream')
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
            raise BrotliError('Decompression error: %s' % ffi.string(error_message))

        size = yield ffi.buffer(out_buffer, buffer_size - available_out[0])[:]

        if rc == lib.BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
            assert available_in[0] == 0
            need_input = True
        elif rc == lib.BROTLI_DECODER_RESULT_SUCCESS:
            break
        else:
            assert rc == lib.BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT

decompress_readers = {
    'gzip': GzipReader,
    'deflate': DeflateReader,
    'br': BrotliReader
    }
