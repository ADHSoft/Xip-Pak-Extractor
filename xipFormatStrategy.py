from abc import abstractmethod
from typing import List, Optional, Set, Tuple, ClassVar, Final
from rsaDecryptor import RsaDecryptor, Rsa3Decryptor


class XipFormatStrategy:

    # class vars:
    rsaDecryptor : ClassVar[Optional[RsaDecryptor]] = None
    environment_ok: ClassVar[bool] = False
    MASKED_VISUALCLIP_FILE_TYPES = {".vci", ".vce",".vc"}
    FILE_HEADER_LENGTH = 0x11c
    FILE_NAME_LENGTH : int
    MASKED_CONFIG_FILE_TYPES : Set[str]
    REQUIRED_KEYS : Set[str]
    # end class vars

    def xipRsaDecrypt(self, *args, **kwargs) -> bytes:
        if XipFormatStrategy.rsaDecryptor is None:
            XipFormatStrategy.rsaDecryptor = RsaDecryptor()
        return XipFormatStrategy.rsaDecryptor.xipRsaDecrypt(*args, **kwargs)
        

class Xip2Decoder(XipFormatStrategy):

    FILE_NAME_LENGTH = 0x104
    MASKED_CONFIG_FILE_TYPES = {".ini", ".crc", ".cvs", ".vgi", ".gsi", ".txt", ".gds"}
    REQUIRED_KEYS = {"key1a.bin", "key1b.bin"}
    
class Xip2ChDecoder(Xip2Decoder):    
    _rsaDecryptor : ClassVar[Optional[RsaDecryptor]] = None

    REQUIRED_KEYS = {"key1a_ch.bin", "key1b_ch.bin"}
    
    def xipRsaDecrypt(self, *args, **kwargs) -> bytes:
        if Xip2ChDecoder._rsaDecryptor is None:
            Xip2ChDecoder._rsaDecryptor = RsaDecryptor(True)
        return Xip2ChDecoder._rsaDecryptor.xipRsaDecrypt(*args, **kwargs)
        
    
class Xip3Decoder(XipFormatStrategy):

    FILENAME_LENGTH = 0x9C # check
    MASKED_CONFIG_FILE_TYPES = {".ini", ".crc", ".cvs", ".vgi", ".gsi", ".txt", ".cgi", ".gdi"}
    REQUIRED_KEYS = {"key1a.bin", "key1b.bin", "key1c.bin", "USB_16128_10.dat"}

    rsa3Decryptor : ClassVar[Optional[Rsa3Decryptor]] = None

    def xipRsaDecrypt(self, *args, **kwargs) -> bytes:
        if Xip3Decoder.rsa3Decryptor is None:
            Xip3Decoder.rsa3Decryptor = Rsa3Decryptor()
        return Xip3Decoder.rsa3Decryptor.xip3RsaDecrypt(*args, **kwargs)