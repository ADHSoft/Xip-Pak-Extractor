from typing import List
import xipDecoder_strategy

def checksumA(a, b, c) -> bool:
    if c == 0:
        #if __debug__: print("Unimplemented border case") TODO?
        b ^= 1
    var1 = a * b
    var1 &= 0xFF
    return var1 == c

def japDeXor(input_: bytes, offset: int , strategy: xipDecoder_strategy.XipDecoderStrategy ) -> bytes:
    assert offset >= 0
    
    xorKey = xipDecoder_strategy.XipDecoderStrategy().japaneseTextXorEncoder()

    output = bytes()
    for i in range( strategy.fileHeaderLength()):
        offset %= len(xorKey)
        byteA = (xorKey[offset] ^ input_[i]).to_bytes(1, "big")
        output += bytearray(byteA)
        offset += 1
    return  output

def deXorTxt(input_: bytes) -> bytes:
    import struct
    with open("./keyFiles/txtCrcMask.bin", "rb") as file:
        key = bytes(file.read())
    key = struct.unpack_from("<256I", key)
    output = bytes()
    key_offset = len(input_) % 0x100
    i = 0
    for i in range(len(input_) // 4):
        inputInt4 = struct.unpack_from("<I", input_, i*4)[0]
        outputInt4 = ( (inputInt4 - key[(key_offset+i) % len(key)]) % 0x100000000 ).to_bytes(4, "big")
        output += outputInt4[::-1]

    # if the input is not a multiple of 4, the last bytes (3,2,or 1) are left as is.
    i = len(input_) % 4
    if i > 0:
        output += input_[-i:]

    return  output

def deXorVisualClip(input_: bytes) -> bytes:
    from xipDecoder_strategy import Crc32Table
    key : List[int] = [Crc32Table()[i] for i in range(Crc32Table.size)]
    offset = 0xED
    output = input_[0:8] # preserve the first 8 bytes.
    for i in range(8, len(input_) ):
        offset %= len(key)
        byteA = ((key[(offset) % 0x100] ^ input_[i]) & 0xFF).to_bytes(1, "big")
        output += bytearray(byteA)
        offset += 1
    return  output
