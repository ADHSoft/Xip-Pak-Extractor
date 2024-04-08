import pstats
import logging, struct, sys, bcolors
from typing import Any, Dict, List, Optional

import functions
import xipDecoder_strategy
from xipDecoder_strategy import XipDecoderStrategy
import os
import numba


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

class RsaDecryptor:
    key1: Optional[bytes] = None
    key2: Optional[bytes] = None

    @staticmethod
    def initializeStaticVars():
        if RsaDecryptor.key1 is None or RsaDecryptor.key2 is None:
            with open("./keyFiles/key1", "rb") as file:
                RsaDecryptor.key1=bytes(file.read())
            with open("./keyFiles/key2", "rb") as file:
                RsaDecryptor.key2=bytes(file.read())

    def __init__(self):
        if RsaDecryptor.key1 is None: RsaDecryptor.initializeStaticVars()

    def xipRsa(self, input_: bytes, keyIndex: int) -> bytes:
        output = bytes()
        assert RsaDecryptor.key1 is not None and RsaDecryptor.key2 is not None

        size=len(input_)
        assert size % 8 == 0
        size //= 8
        for i in range(size): # decrypt 8 bytes to 4 in each cycle.
            input_a = struct.unpack_from('<Q', input_, 8*i)[0]
            key1 = struct.unpack_from('<Q', RsaDecryptor.key1, 8*keyIndex)[0]
            key2 = struct.unpack_from('<Q', RsaDecryptor.key2, 8*keyIndex)[0]
            var1 = xipRsa1(input_a, key2, key1)
            output += struct.pack("<I",var1)

            keyIndex += 1
            keyIndex %= 256 # len(key1data) // 8
        return output


class PackagedFile:
    """
    structure of a file block for xip2:

    0x11c bytes : xored data with the japanese text
        4 bytes: fileBlockSize (size of the whole file block)
        4 bytes: size of the final file once decompressed and everything
        4 bytes: unknown1 # some may be a hash of the filename or something to easily find the file
        0x104 bytes : path+filename , zero terminated, 0xCC padding, encoding could vary.
        4 bytes: crc32 of the final extracted file but before the additional xoring for .txt , etc
        4 bytes: unknown2
        1 byte: cryptKeyIndex (for the rsa-like decryption of the cryptChunk)
        3 bytes: unknown3 , could be just the rest of the above byte that may come from randint32()

    4 bytes: _size1 , cryptChunkSize   but with bits shuffled
    4 bytes: _size2 , rsaDecryptedSize but with bits shuffled

    (cryptChunkSize) bytes : cryptChunk , it's the beginning of the compressed data, encrypted. Some parts could look like raw data because of a flaw in the encryption algorithm.

    x bytes : rest of the file (compressed) 

    """
    #instance variables:

    fileDescriptor: bytes # all bytes of the header    
    
    fileName: str
    baseOffset: int # address in the xip file
    uncompressedSize: int
    crc32: int
    cryptKeyIndex: int
    fileBlockSize: int # how much to jump to the next file header
    

    xorParam: int
    format_: XipDecoderStrategy

    fileDataCompressed: bytes # file content after decryption

    finalData: bytes

    #for debug:
    decryptedData: bytes
    noErrors: bool
    fileIndex: Optional[int]

    def __init__(self, xipFile, baseOffset, xorKeyOffset, format_: XipDecoderStrategy, fileIndex: Optional[int] = None):
        self.finalData = bytes()
        self.xipFile = xipFile
        self.noErrors = True
        self.fileIndex = fileIndex
        self.xorParam = xorKeyOffset
        self.baseOffset = baseOffset
        self.format_ = format_


        self.fileDescriptor = functions.japDeXor(xipFile[baseOffset: baseOffset + format_.fileHeaderLength()], xorKeyOffset , format_)

        a = self.fileDescriptor[0x0c:(0x0c + format_.fileNameLength())]
        a = a[ : a.find(b'\x00')]

        fileName: Optional[str] = None
        import os
        for enc in ["ascii", "shift-jis", "EUC-KR", "utf-8" ]:
            try:
                fileName = a.decode( enc )
                os.access(fileName, os.W_OK)
                break
            except UnicodeDecodeError:  # wrong encoding
                fileName = None
            except ValueError:          # windows impossible filename
                fileName = None
        if fileName is None:
            raise Exception("Could not decode the file name.")
        self.fileName = fileName

        # TODO: final touch when it all works: remove magic numbers of the below lines.

        self.fileBlockSize , self.uncompressedSize = struct.unpack_from('<II', self.fileDescriptor, 0)
        self.cryptKeyIndex = self.fileDescriptor[0x118]
        self.crc32 = struct.unpack_from('<I', self.fileDescriptor, 0x110)[0]


    def extractAsync(self) -> Dict[ Any, Any ] :
        '''
        This extracts the file content, it's compatible with async and parallel procesing.
        '''
        
        self._size1 , self._size2 = struct.unpack_from('<II', self.xipFile[self.baseOffset + 0x011C : (self.baseOffset + 0x011C + 8 )])

        A1 = self._size1
        A2 = self._size2
        cryptChunkSize = (((A2 >> 8 & 0xff) << 8 | A1 & 0xff) << 8 | A1 >> 0x18) << 8 | A1 >> 8 & 0xff         
        rsaDecryptedSize = (((A1 >> 0x10 & 0xff) << 8 | A2 >> 0x18) << 8 | A2 & 0xff) << 8 | A2 >> 0x10 & 0xff 
        #offsetToStartOverwriting = (cryptChunkSize - rsaDecryptedSize) + 8 + 0x11c + self.baseOffset   #  writeZoneStartAddr
        
        try: 
            off1=8 + 0x11c + self.baseOffset 
            self.decryptedData = RsaDecryptor().xipRsa( self.xipFile[off1:off1+rsaDecryptedSize*2] , self.cryptKeyIndex)
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

        import lzo
        # unfortunately, the line below could suddenly crash python.exe because it's a C dll which will crash if the output buffer allocated (for the expected decompressed size) gets overflowed (because of a badly formed data) , even in a try-except block.
        dataout=lzo.decompress(fileDataCompressed  , False, self.uncompressedSize,  algorithm="LZO1X")
        
        return {"index": self.fileIndex, "error":False, "finalData": dataout}
    
    def extractFileAsyncComplete( self ):
        enableCrcCheck:bool = False

        fileData = self.extractAsync()
        if not self.noErrors:
            raise Exception(f"{bcolors.ERR}Exception when decompressing '{self.fileName}'{bcolors.ENDC}")
        
        dataout = fileData["finalData"]

        # additonal decryption for some file types
        if len(self.fileName.split("\\")[-1]) > 3:
            extension: str = self.fileName.split("\\")[-1][-4:]
            if extension in self.format_.maskedFileTypes_ConfigFile():
                dataout = functions.deXorTxt(dataout)

        crcOk: bool
        if enableCrcCheck:
            import zlib    
            crcCalculated : int = zlib.crc32(dataout)
            crcOk =  self.crc32 == crcCalculated
        else:
            crcOk = True
        
        if len(self.fileName.split("\\")[-1]) > 3:
            extension: str = self.fileName.split("\\")[-1][-4:]
            if extension in self.format_.maskedFileTypes_VisualClip():
                dataout = functions.deXorVisualClip(dataout)
        
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
    def unknown3b(self):
        return self.fileDescriptor[0x118 : 0x11c ]


def openXip(pakFilename:str , enableParallel:bool = False ) :
    with open("./inputFiles/"+pakFilename, "rb") as xipFile:
        xipFile=bytes(xipFile.read())
    if xipFile[0:3] != b"XIP":
        raise Exception("Not a valid XIP file.")
    
    xipDecoder : XipDecoderStrategy
    
    if xipFile[3:4] == b"2":
        xipDecoder = xipDecoder_strategy.Xip2Decoder()
    elif xipFile[3:4] == b"3":
        xipDecoder = xipDecoder_strategy.Xip3Decoder()
    else:
        raise Exception("Not a compatible XIP file.")
    
    if xipDecoder.environment_ok == False:
        for key in xipDecoder.required_keys():
            if key not in os.listdir("./keyFiles"):
                raise Exception(f"Can't execute extractor, missing key file: {key}")
        xipDecoder.environment_ok = True
        if 'key' in locals(): del key


    offsetSecretA: bytes = xipFile[4:5]+xipFile[6:7]+xipFile[8:9]+xipFile[11:12]
    offsetSecretA = struct.unpack_from('<I', offsetSecretA)[0]
    secretASkipSize = xipFile[9:10] + xipFile[7:8]
    secretASkipSize = struct.unpack_from('<H', secretASkipSize)[0]

    secretA = xipFile[offsetSecretA:int(offsetSecretA)+24]
    if type(xipDecoder) == xipDecoder_strategy.Xip3Decoder:
        ... # TODO add 0x98989898 step
        raise NotImplementedError
    secretA = RsaDecryptor().xipRsa(secretA,0x0c)

    fileOffset : int
    numberOfFiles : int
    _ , fileOffset , numberOfFiles , checksumAData , _ = struct.unpack( '<H I I B B', secretA)

    functions.checksumA(fileOffset&0xff,numberOfFiles&0xff,checksumAData)

    files : List[PackagedFile] = []
    for fileNumber in range(numberOfFiles):
        if fileOffset == offsetSecretA:
            fileOffset += secretASkipSize
        pf = PackagedFile(xipFile, fileOffset, (numberOfFiles - fileNumber), xipDecoder, fileNumber)
        files.append(pf)
        fileOffset += xipDecoder.fileHeaderLength() + pf.fileBlockSize
        if not pf.noErrors :
            logging.debug(f"{bcolors.ERR}Parsing failed for some file{bcolors.ENDC}")            
            continue
        #logging.debug(pf.fileName)   

    if listFiles := False:
        for pf in files:
            print(pf.fileName)

    if extractFiles := True :
        pathsToMake = set()
        for pf in files:
            # make folder structure synchronously
            path = pf.fileName.split("\\")
            if any( [ p in [".", ".."] for p in path ] ):
                print(f"This filename/path is not supported for security reasons: {pf.fileName}") # this is not optimal
                continue
            if len(path) > 1:
                folder = path[:-1]
                folder = "\\".join(folder)
                pathsToMake.add(f"./outFiles/{folder}")            
        
        for path in pathsToMake:
            os.makedirs(path, exist_ok=True)

        for i, pf in enumerate(files):
            try:
                if not pf.noErrors :
                    print(f"{bcolors.ERR}Exception when parsing '{pf.fileName}'{bcolors.ENDC}")
                else:
                    result = pf.extractFileAsyncComplete()
                    finalPath = f"./outFiles/" + pf.fileName.replace('\\','/')
                    
                    os.access( os.path.dirname(finalPath), os.W_OK)

                    with open( finalPath, "wb") as file:
                        file.write(result["finalData"])

                    print(f"{i+1}/{len(files)} files completed.", end="\r", flush=True)

                    if not result["crcOk"]:
                        print(f"{bcolors.ERR}CRC32 check failed for '{pf.fileName}'{bcolors.ENDC}")

            except Exception as e:
                print(f"{bcolors.ERR}Exception when decompressing '{pf.fileName}'{bcolors.ENDC}")
                print(e)
        print("")


    print(f"Done {pakFilename}.")

    return files


def main_profile(fileName : str = "./System.pak"):
    import cProfile

    logging.basicConfig(level=logging.ERROR)
    cProfile.run(f"openXip('{fileName}')", "profile_output.prof", sort="cumulative" )
    stats = pstats.Stats("profile_output.prof")
    stats.sort_stats('cumulative')
    stats.print_stats(30)

def main(fileName : str = "./System.pak"):

    logging.basicConfig(level=logging.ERROR)
    openXip(fileName)

def openMany():
    files = os.listdir("./inputFiles/")
    for file_ in files:
        if len(file_) > 4 and file_[-4:] == ".pak":
            print(f"Extracting {file_.split('/')[-1]}")
            openXip(file_)

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "./System.pak")
    
    #openMany()   

