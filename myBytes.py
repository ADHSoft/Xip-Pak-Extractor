import logging
from typing import Optional

from attr import define


'''
Helper class to improve bytes handling
This is not made very properly, it can have performance impacts.
'''
@define( init=True )
class Bytes:
    # instance variables:
    value: bytes = bytes()  # stored in big endian

    @classmethod
    def fromLazyIntLE(cls, input_: int, LEndian: bool = True, size: Optional[int] = None):
        if size is None:
            size = len(bytearray.fromhex(str(hex(input_)[2:])))  # "2:" to remove str "0x"
        if LEndian:
            ba = input_.to_bytes(length=size, byteorder="little")
        else:
            ba = input_.to_bytes(length=size, byteorder="big")
        return cls.fromBytes(ba)

    def __sizeof__(self):
        return len(self.value)

    @classmethod
    def fromBytes(cls, value: bytes, useSizePowerOfTwo: bool = True):
        #TODO check
        print("untested 151903") 
        if len(value) == 0: raise ValueError
        if useSizePowerOfTwo:
            while len(value) not in [1, 2, 4, 8, 16, 32, 64]:
                logging.debug("warning: extending byte array, only works if size is a power of two")
                if len(value) > 64: raise NotImplementedError
                value = bytes.fromhex("00") + value
        return cls(value)

    def __int__(self):
        return int.from_bytes(self.value)

    @classmethod
    def fromStrLE(cls, input_: str, LEndian: bool = True):
        input_=input_.replace(" ", "")
        ba = bytearray.fromhex(input_)
        if LEndian: ba.reverse()
        return cls.fromBytes(ba,False)

    def __index__(self):  # this is to override __hex__
        return int(self.value)

    
def printableBytes(a: bytes , add0x: bool = True) -> str:
    data:str = str(hex(int.from_bytes(a, byteorder='big')))
    data = data.replace("0x", "")
    if len(data) % 2 != 0:
        data = "0" + data
    if add0x:
        return "0x" + data
    else:
        return data 