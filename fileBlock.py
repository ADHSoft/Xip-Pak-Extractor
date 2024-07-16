import struct, os
from typing import Any, Dict, Optional
import lzo, bcolors, etcXorers


from rsaDecryptor import RsaDecryptor
from xipFormatStrategy import Xip3Decoder, XipFormatStrategy
class FileBlock:
    """
    structure of a file block for xip2:

    0x11c bytes : xored data with the japanese text
        4 bytes: fileBlockSize (size of the whole file block)
        4 bytes: size of the final file once decompressed and everything
        4 bytes: unknown1 # some may be a hash of the filename or something to easily find the file-
        0x104 bytes : path+filename , zero terminated, 0xCC padding, encoding could vary?
        4 bytes: crc32 of the final extracted file but before the additional xoring for .vce
        4 bytes: unknown2
        1 byte: cryptKeyIndex (for the rsa-like decryption of the cryptChunk)
        3 bytes: unknown3 , could be just the rest of the above byte that may come from something like random_int32() ?

    4 bytes: _size1 , cryptChunkSize   but with bits shuffled
    4 bytes: _size2 , rsa-likeDecryptedSize but with bits shuffled

    (cryptChunkSize) bytes : cryptChunk , it's the beginning of the compressed data, encrypted. Some parts could be the same as the raw data because of a flaw in the encryption algorithm.

    x bytes : rest of the file (compressed) 

    """
    
    fileDescriptor: bytes # all bytes of the header    
    
    fileName: str
    baseOffset: int # address in the xip file
    uncompressedSize: int
    crc32: int
    cryptKeyIndex: int
    fileBlockSize: int # how much to jump to the next file header
    

    xorParam: int
    format_: XipFormatStrategy

    fileDataCompressed: bytes # file content after decryption

    finalData: bytes

    #for debug:
    decryptedData: bytes
    noErrors: bool
    fileIndex: Optional[int]

    def __init__(self, xipFile, baseOffset, xorKeyOffset, format_: XipFormatStrategy, fileIndex: Optional[int] = None):
        self.finalData = bytes()
        self.xipFile = xipFile
        self.noErrors = True
        self.fileIndex = fileIndex
        self.xorParam = xorKeyOffset
        self.baseOffset = baseOffset
        self.format_ = format_

        if isinstance(format_, Xip3Decoder):
            self.key = struct.unpack_from('<Q',  xipFile[baseOffset+8: baseOffset+8 + 8])[0] % 0x7d
            raise NotImplementedError
            key = usbkey[self.key]
            for i in range(0x9c):
                if i % 4 == 0:
                    xipFile[baseOffset+i] ^= key
            



        self.fileDescriptor = etcXorers.japUnXor(xipFile[baseOffset: baseOffset + format_.FILE_HEADER_LENGTH], xorKeyOffset , format_)

        a = self.fileDescriptor[0x0c:(0x0c + format_.FILE_HEADER_LENGTH)]
        a = a[ : a.find(b'\x00')]

        fileName: Optional[str] = None
        for enc in ["ascii", "shift-jis", "EUC-KR", "utf-8" ]:
            try:
                fileName = a.decode( enc )
                os.access(fileName, os.W_OK) # this is to check if path+name is valid
                break
            except UnicodeDecodeError:  # wrong encoding
                fileName = None
            except ValueError:          # windows impossible filename
                fileName = None
        if fileName is None:
            raise Exception("Could not decode the file name.")
        self.fileName = fileName

        self.fileBlockSize , self.uncompressedSize = struct.unpack_from('<II', self.fileDescriptor, 0)
        self.cryptKeyIndex = self.fileDescriptor[0x118]
        self.crc32 = struct.unpack_from('<I', self.fileDescriptor, 0x110)[0]


    def extract(self) -> Dict[ str, Any ] :
        
        self._size1 , self._size2 = struct.unpack_from('<II', self.xipFile[self.baseOffset + 0x011C : (self.baseOffset + 0x011C + 8 )])

        A1 = self._size1
        A2 = self._size2
        cryptChunkSize =   (((A2 >> 8 & 0xff) << 8 | A1 & 0xff) << 8 | A1 >> 0x18) << 8 | A1 >> 8 & 0xff         
        rsaDecryptedSize = (((A1 >> 0x10 & 0xff) << 8 | A2 >> 0x18) << 8 | A2 & 0xff) << 8 | A2 >> 0x10 & 0xff 
        #offsetToStartOverwriting = (cryptChunkSize - rsaDecryptedSize) + 8 + 0x11c + self.baseOffset   #  writeZoneStartAddr
        
        try: 
            off1=8 + 0x11c + self.baseOffset 
            self.decryptedData = self.format_.xipRsaDecrypt( self.xipFile[off1:off1+rsaDecryptedSize*2] , self.cryptKeyIndex)
        except Exception as e:
            self.noErrors = False
            raise e
        
        '''# TODO : there's this loop that could be executed (timesLoopX) times, for big files?
            for (A2 = A2 >> 0x10 & 3; A2 != 0; A2 = A2 - 1) {
            *(byte *)writeZoneAddr = *(byte *)RSADecryptedIncrPointer;
            RSADecryptedIncrPointer = (dword *)((int)RSADecryptedIncrPointer + 1);
            writeZoneAddr = (dword *)((int)writeZoneAddr + 1);
        }
        '''
        timesLoopX = (A2 >> 16) & 3  #(0,1,2,3)  
        if timesLoopX != 0:
            raise NotImplementedError        
        
        sizeOfEncryptedData: int = cryptChunkSize

        unCryptDataOff = self.baseOffset + 0x011C + 8 + sizeOfEncryptedData

        fileDataCompressed = self.decryptedData + self.xipFile [ unCryptDataOff : unCryptDataOff + self.fileBlockSize - 8 - sizeOfEncryptedData ]
                
        #if __debug__:
        #    self.fileDataCompressed = fileDataCompressed

        
        # unfortunately, the line below could suddenly crash python.exe because it's a C dll which will crash if the output buffer allocated (for the expected decompressed size) gets overflowed (because of a badly formed data) , even in a try-except block.
        dataout=lzo.decompress(fileDataCompressed  , False, self.uncompressedSize, algorithm="LZO1X")
        
        return {"index": self.fileIndex, "error":False, "finalData": dataout}
    
    def extractFile( self ):
        enableCrcCheck:bool = False

        fileData = self.extract()
        if not self.noErrors:
            raise Exception(f"{bcolors.ERR}Exception when decompressing '{self.fileName}'{bcolors.ENDC}")
        
        dataout = fileData["finalData"]

        # additonal decryption for some file types
        if len(self.fileName.split("\\")[-1]) > 3:
            extension: str = self.fileName.split("\\")[-1][-4:]
            if extension in self.format_.MASKED_CONFIG_FILE_TYPES:
                dataout = etcXorers.unmaskTxt(dataout)

        crcOk: bool
        if enableCrcCheck:
            import zlib    
            crcCalculated : int = zlib.crc32(dataout)
            crcOk =  self.crc32 == crcCalculated
        else:
            crcOk = True

        
        if len(self.fileName.split("\\")[-1]) > 3:
            extension: str = "." + self.fileName.split("\\")[-1].split(".")[-1]
            if extension in self.format_.MASKED_VISUALCLIP_FILE_TYPES:
                if extension == ".vc":
                    dataout = etcXorers.unXorVisualClip(dataout, True)
                else:
                    dataout = etcXorers.unXorVisualClip(dataout)
        
        return_ =  {"index": self.fileIndex, "crcOk": crcOk, "finalData": dataout }

        return return_


    @property
    def unknown1(self):
        return  self.fileDescriptor[0x8 : 0x0c]     # 4 bytes

    @property
    def unknown2(self):
        return  self.fileDescriptor[0x114 : 0x118]  # 4 bytes
    
    @property
    def unknown3(self):
        return self.fileDescriptor[0x119 : 0x11c ]   # 3 bytes
    @property
    def unknown3_4BB(self):
        return self.fileDescriptor[0x118 : 0x11c ]