from functools import cache
from typing import List, Literal, Optional, Tuple, Union
import xipFormatStrategy
import struct


class Crc32Table: #  256 32bit numbers
    size : int = 256
    _table : Optional[Tuple] = None
    _tableHex : Optional[bytes] = None

    def __init__(self) -> None:
        if Crc32Table._table is None:
            table = [0 for _ in range(Crc32Table.size)]
            Crc32Table._tableHex = bytes()
            for i in range(Crc32Table.size):
                crc = i
                for _ in range(8):
                    crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
                table[i] = crc
                Crc32Table._tableHex += crc.to_bytes(4, "little") # type: ignore
            Crc32Table._table = tuple(table)

    def get(self, index:int) -> int:
        if Crc32Table._table is None:
            Crc32Table()
        index &= 255
        assert Crc32Table._table is not None
        return Crc32Table._table[index]
    
    def getTable(self) -> bytes:
        if Crc32Table._tableHex is None:
            Crc32Table()
        assert Crc32Table._tableHex is not None
        return Crc32Table._tableHex


    def __index__(self, index: int) -> int:
        return Crc32Table().get(index)
    
    def __getitem__(self, index: int) -> int:
        return Crc32Table().get(index)
    
class VcKey:
    key : Optional[bytes] = None

    @staticmethod
    def get() -> bytes:
        if VcKey.key is None:
            VcKey()
        assert VcKey.key is not None    
        return VcKey.key
    
    def __init__(self) -> None:
        if VcKey.key is None:
            VcKey.key = bytes(Crc32Table().get(i)&0xff for i in range(256))

def unXorVisualClip(input_: bytes, vc:bool = False ) -> bytes:
    key : bytes = VcKey().get()
    output = bytearray(input_[:]) 
    offset: int = 0xED
    if vc:
        offset += 9
    for i in range(8, len(input_) ):# preserve the first 8 bytes.
        offset &= 255 #len(key)
        output[i] = key[offset % 256] ^ input_[i]
        offset += 1
    return output

   
@cache
def japaneseTextXorEncoder(alt: bool = False) -> bytes:
    start = 0 if alt else 1
    japText : str = """……耕一さん……あなたを殺します
私はあなたを、愛してはいませんから…
生きて…ラカン…
百年…貴方を待っていたの…千年…貴方に恋していたわ
私…世界より貴方がほしい……
夜空に星が輝くように溶けた心は離れない
たとえこの手が離れてもふたりがそれを忘れぬ限り"""
    return japText.replace("\n","\r\n").encode("shift-jis")[start:(start+256)] 

def japUnXor_(input_: bytes, keyOffset: int , size:int , alt: bool = False ) -> bytes:
    keyOffset &= 255
    
    xorKey = japaneseTextXorEncoder( alt )

    output = bytes()
    for i in range( size ):
        byteA = (xorKey[keyOffset] ^ input_[i]).to_bytes(1, "big")
        output += bytearray(byteA)
        keyOffset += 1
        keyOffset &= 255 #len(xorKey)
    return  output


def japUnXor(input_: bytes, keyOffset: int , strategy: xipFormatStrategy.XipFormatStrategy ) -> bytes:
    return japUnXor_(input_, keyOffset, strategy.FILE_HEADER_LENGTH)

@cache
def txtKey() -> Tuple[int]:   

    vckey = Crc32Table().getTable()
    key = vckey[0x70:0xA0] + vckey[0x30:0x70]  + vckey[0xA0:0x100] + vckey[0x00:0x30]  + vckey[0x180:0x200] + vckey[0x100:0x180] + vckey[0x270:0x2B0] + vckey[0x210:0x270] + vckey[0x2B0:0x300] + vckey[0x200:0x210] + vckey[0x370:0x400] + vckey[0x300:0x370]
    return struct.unpack_from("<256I", key )

def unmaskTxt(input_: bytes) -> bytes:

    key = txtKey()
    output = bytes()
    key_offset = len(input_) % 0x100
    i = 0
    for i in range(len(input_) // 4):
        inputInt4 = struct.unpack_from("<I", input_, i*4)[0]
        outputInt4 = ( (inputInt4 - key[(key_offset+i) % len(key)]) % 0x100000000 ).to_bytes(4, "big")
        output += outputInt4[::-1]

    # if the input is not a multiple of 4, the last bytes (3,2,or 1) aren't actually masked.
    i = len(input_) % 4
    if i > 0:
        output += input_[-i:]

    return output

            
def checksumA(a:int , b:int, c:int) -> bool:
    if c == 0:
        #if __debug__: print("Unimplemented border case") TODO?
        b ^= 1
    var1 = (a * b) & 0xFF
    return var1 == c