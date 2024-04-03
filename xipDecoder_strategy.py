from abc import abstractmethod
from functools import cache
from typing import List
import japText


# Many methods could use @property and @staticmethod decorators , but I don't want to make the code too verbose right now.

class XipDecoderStrategy:
    @cache # ( don't recalculate )
    def japaneseTextXorEncoder(self) -> bytes:
        text: str = japText.japText
        return text.replace("\n","\r\n").encode("shift-jis")[1:(1+256)]
    
    def maskedFileTypes_VisualClip(self) -> List[str]:
        return [".vci", ".vce"]
    
    @abstractmethod
    def fileHeaderLength(self) -> int:
        ...

    @abstractmethod
    def fileNameLength(self) -> int:
        ...

    @abstractmethod
    def maskedFileTypes_ConfigFile(self) -> List[str]:
        ...

    @abstractmethod
    def required_keys(self) -> List[str]:
        ...
        

class Xip2Decoder(XipDecoderStrategy):
    # class variables:
    environment_ok: bool = False

    def fileHeaderLength(self) -> int:
        return 0x11c
    
    def fileNameLength(self) -> int:
        return 0x104
    
    def maskedFileTypes_ConfigFile(self) -> List[str]:
        # they made a typo, 'cvs' instead of 'csv'
        return [".ini", ".crc", ".cvs", ".vgi", ".gsi", ".txt", ".gds"]
    
    def required_keys(self) -> List[str]:
        return ["key1", "key2", "txtCrcMask.bin"] 
        
    
class Xip3Decoder(XipDecoderStrategy):
    # class variables:
    environment_ok: bool = False

    def fileHeaderLength(self) ->int:
        # 9c ?
        raise NotImplementedError
    
    def fileNameLength(self) -> int:
        return 0x80
    
    def maskedFileTypes_ConfigFile(self) -> List[str]:
        return [".ini", ".crc", ".cvs", ".vgi", ".gsi", ".txt", ".cgi", ".gdi"]
    
    def required_keys(self) -> List[str]:
        return ["key1", "key2", "key3", "txtCrcMask.bin", "USB_16128_10.dat"]


class Crc32Table: # a.k.a. "vcKey", 256 32bit numbers
    # class variables:
    size : int = 256

    @staticmethod
    @cache
    def __index__(index: int) -> int:
        crc: int = index
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
        return crc
    def __getitem__(self, index: int) -> int:
        return self.__index__(index % Crc32Table.size)