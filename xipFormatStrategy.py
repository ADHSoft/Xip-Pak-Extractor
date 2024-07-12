from abc import abstractmethod
from typing import List, Optional, Set, Tuple
from rsaDecryptor import RsaDecryptor


class XipFormatStrategy:

    # class vars:
    MASKED_VISUALCLIP_FILE_TYPES = {".vci", ".vce",".vc"}
    rsaDecryptor : Optional[RsaDecryptor] = None
    environment_ok: bool = False
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
    _rsaDecryptor : Optional[RsaDecryptor] = None

    REQUIRED_KEYS = {"key1a_ch.bin", "key1b_ch.bin"}
    
    def xipRsaDecrypt(self, *args, **kwargs) -> bytes:
        if Xip2ChDecoder._rsaDecryptor is None:
            Xip2ChDecoder._rsaDecryptor = RsaDecryptor(True)
        return Xip2ChDecoder._rsaDecryptor.xipRsaDecrypt(*args, **kwargs)
        
    
class Xip3Decoder(XipFormatStrategy):

    FILENAME_LENGTH = 0x9C # check
    MASKED_CONFIG_FILE_TYPES = {".ini", ".crc", ".cvs", ".vgi", ".gsi", ".txt", ".cgi", ".gdi"}
    REQUIRED_KEYS = {"key1a.bin", "key1b.bin", "key1c.bin", "USB_16128_10.dat"}

    def __init__(self) -> None:
        raise NotImplementedError()