import struct
from typing import Optional
import numba


class WrongKeysError(Exception):
    pass

@numba.njit()
def xipRsa2(inputB: int, input_: int, key: int) -> int:
    '''decoded = (encoded **e) %m
    decoded = (inputB ** input) % key
    https://en.wikipedia.org/wiki/Modular_exponentiation#:~:text=)-,Pseudocode,-%5Bedit%5D
    https://en.wikipedia.org/wiki/RSA_(cryptosystem)#:~:text=calculations%20can%20be-,computed%20efficiently,-using%20the%20square
    '''
    output = 0
    while input_ != 0:
        if input_ % 2 == 1:
            output = (inputB + output) % key
        inputB *= 2
        inputB %= key
        input_ //= 2
    return output

@numba.njit()
def xipRsa1(input_: int, key2: int, key1: int) -> int:
    # input: 8Btyes. output: 4Bytes
    output = 1
    while key2 != 0:
        if key2 % 2 == 1:
            output = xipRsa2(output, input_, key1)
        input_ = xipRsa2(input_, input_, key1)
        key2 //= 2
    return output

class RsaDecryptor: # RSA-like decryption
    key1: bytes
    key2: bytes

    def __init__(self, chKeyMode: bool = False):
        with open(f'./keyFiles/key1a{"_ch" if chKeyMode else ""}.bin', "rb") as file_:
            self.key1=bytes(file_.read())
        with open(f'./keyFiles/key1b{"_ch" if chKeyMode else ""}.bin', "rb") as file_:
            self.key2=bytes(file_.read())

    def xipRsaDecrypt(self, input_: bytes, keyIndex: int) -> bytes:
        output = bytes()

        size=len(input_)
        assert size % 8 == 0
        size //= 8
        for i in range(size): # decrypt 8 bytes to 4 in each cycle.
            input_a = struct.unpack_from('<Q', input_, 8*i)[0]
            key1 = struct.unpack_from('<Q', self.key1, 8*keyIndex)[0]
            key2 = struct.unpack_from('<Q', self.key2, 8*keyIndex)[0]
            var1 = xipRsa1(input_a, key2, key1)
            output += struct.pack("<I",var1)

            keyIndex += 1
            keyIndex %= 256 # len(key1data) // 8
        return output
    