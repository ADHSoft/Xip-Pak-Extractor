"""import ctypes
from ctypes import CDLL, c_char_p, c_int, c_void_p, c_ubyte

lzoDll = CDLL("./myLzoDll.dll")
lzoDll.MyLzoDll_decompressData.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),  # compressedData
    ctypes.c_uint,                   # compressedSize
    ctypes.POINTER(ctypes.c_ubyte),  # decompressedData
    ctypes.c_uint                    # decompressedSize
]
lzoDll.MyLzoDll_decompressData.restype = c_int


a = (c_ubyte * len(cf.fileDataCompressed))(*cf.fileDataCompressed)
compressed_data_ptr = ctypes.cast(a, ctypes.POINTER(ctypes.c_ubyte))

bufferOut = (c_ubyte * (cf.uncompressedSize + 1000))() # 1000 bytes extra for testing
decompressed_data_ptr = ctypes.cast(bufferOut, ctypes.POINTER(ctypes.c_ubyte))


dllResult : int = lzoDll.MyLzoDll_decompressData(compressed_data_ptr, len(cf.fileDataCompressed), bufferOut, cf.uncompressedSize)



bufferOut = ctypes.cast(decompressed_data_ptr, ctypes.POINTER(ctypes.c_ubyte * cf.uncompressedSize)).contents

if dllResult == 0:
    dataout = bytes(bufferOut)"""