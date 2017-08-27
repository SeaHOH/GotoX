# coding:utf-8
# IOReader-like object wrapper for brotlipy decompress
# https://github.com/python-hyper/brotlipy
# 由于是用于解压 HTTP 响应内容，无需再次实现读取缓冲
# 使用 Decompressor 效率较低，需在更基础的层次重构解压过程

from brotli import Decompressor

class BrotliReader:
    def __init__(self, fileobj):
        self.decompressor = Decompressor()
        self.fp = fileobj
        self.data = None

    def read(self, size=-1):
        if size > 0:
            b = bytearray(size)
            n = self.readinto(b)
            return memoryview(b)[:n].tobytes()
        else:
            data = self.fp.read()
            return self.decompressor.decompress(data)

    def readinto(self, b):
        if self.fp is None:
            return 0
        bsize = len(b)
        size = bsize // 5
        l = 0
        data = self.data
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
                self.data = None
        while True:
            data = self.fp.read(size)
            if not data:
                self.fp = None
                self.decompressor.finish()
                break
            data = memoryview(self.decompressor.decompress(data))
            dsize = len(data)
            e = l + dsize
            if e > bsize:
                self.data = data
                self.p = p = dsize + bsize - e
                b[l:] = data[:p]
                l = bsize
                break
            else:
                b[l:e] = data[:]
                l = e
        return l
