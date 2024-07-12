import hashlib
from myBytes import Bytes
import rsaDecryptor, etcXorers

def tests(): 
    try:
        if not __debug__:
            a="Debug mode is disabled. Asserts and tests won't work."
            print(a)
            raise Exception()

        dataInput = Bytes.fromStrLE(" 6F A0 02 6A F9 97 2F 00  ")
        key1 = Bytes.fromStrLE(" 5B 0A 1D 7F 42 7C 47 00  ")
        key2 = Bytes.fromStrLE(" C1 3A E8 33 2C A8 2F 00 ")
        ans = rsaDecryptor.xipRsa1(int(dataInput), int(key2), int(key1))
        assert hex(ans) == "0xab1102"

        ans = rsaDecryptor.xipRsa2(1, int(dataInput), int(key1))
        assert hex(ans) == "0x2f97f96a02a06f"

        dataInput = bytearray(b'o\xa0\x02j\xf9\x97/\x00\x00\x00~\x00\x00\x00\x00\x00\xbaHu\xbe?"\x0b\x00')
        ans=rsaDecryptor.RsaDecryptor().xipRsaDecrypt(dataInput,0x0c)
        assert hex(int.from_bytes(ans, byteorder='big')) == "0x211ab0000007e000000012a"

        assert hashlib.md5(etcXorers.japaneseTextXorEncoder()).hexdigest() == '74615d959b2d008869dc8fd289686702'

        print("TESTS OK!")
    except Exception:
        print("TESTS NOT OK .")

if __name__ == "__main__":
    tests()