import hashlib, logging, struct, sys
from pprint import pprint
from typing import List, Optional

import tests, functions
from myBytes import Bytes
import xipDecoder_strategy
from xipDecoder_strategy import XipDecoderStrategy
import os


'''decoded = (encoded **e) %m
decoded = (inputB ** input) % key
https://en.wikipedia.org/wiki/Modular_exponentiation#:~:text=)-,Pseudocode,-%5Bedit%5D
https://en.wikipedia.org/wiki/RSA_(cryptosystem)#:~:text=calculations%20can%20be-,computed%20efficiently,-using%20the%20square
'''
def xipRsa2(inputB: int, input_: int, key: int) -> int:
    output = 0
    while input_ != 0:
        if input_ % 2 == 1:
            output = (inputB + output) % key
        inputB *= 2
        inputB %= key
        input_ //= 2
    return output


def xipRsa1(input_: int, key2: int, key1: int) -> int:
    # input: 8Btyes. output: 4Bytes
    output = 1
    while key2 != 0:
        if key2 % 2 == 1:
            output = xipRsa2(output, input_, key1)
        input_ = xipRsa2(input_, input_, key1)
        key2 //= 2
    return output

def xipRsa(input_: bytes, keyIndex: int) -> bytes:
    output = bytes()
    with open("./keyFiles/key1", "rb") as file:
        key1data=bytes(file.read())
    with open("./keyFiles/key2", "rb") as file:
        key2data=bytes(file.read())
    size=len(input_)
    assert size % 8 == 0
    size //= 8
    for i in range(size): # decrypt 8 bytes to 4 in each cycle.
        input_a = struct.unpack_from('<Q', input_, 8*i)[0]
        key1 = struct.unpack_from('<Q', key1data, 8*keyIndex)[0]
        key2 = struct.unpack_from('<Q', key2data, 8*keyIndex)[0]
        var1 = xipRsa1(input_a, key2, key1)
        output += struct.pack("<I",var1)

        keyIndex += 1
        keyIndex %= len(key1data) // 8
    return output


class PackagedFile:
    """
    structure of a file block for xip2:

    0x11c bytes : xored data with the japanese text
        4 bytes: fileBlockSize (size of the whole file block)
        4 bytes: size of the final file once decompressed and everything
        4 bytes: unknown1
        0x104 bytes : path+filename , zero terminated, 0xCC padding, encoding could vary.
        4 bytes: crc32 of the final file
        4 bytes: unknown2
        1 byte: cryptKeyIndex (for the rsa-like decryption of the cryptChunk)
        3 bytes: unknown3

        TODO check if one of the unknown data is crc32 for the compressed stage of the file.

    4 bytes: unknownA1 , looks like it's always 0x00500000
    4 bytes: unknownA2 , looks like it's always 0x00002800

    4*x bytes : 00 padding ?? (most times x is 0.) This could be totally incorrect, because of the related cryptChunk research being made.

    0x50 bytes : cryptChunk , it's the beginning of the file (compressed still), mostly encrypted. it's a mix of raw data and rsa-like encrypted data. Still don't know what determines which parts are encrypted and which are not. But I hardcoded a combination that works for most files.
    It's made of 8 byte blocks. when a block is of just raw data, its content will be 4bytes of data and 4bytes of zero padding.
    Named it "shuffling algorithm" in the code.

    x bytes : rest of the file (compressed data) 

    """
    #instance variables:

    fileDescriptor: bytes # all bytes of the header    
    
    fileName: str
    baseOffset: int # address in the xip file
    fileDataCompressedSize : int
    uncompressedSize: int
    crc32: int
    cryptKeyIndex: int
    fileBlockSize: int # how much to jump to the next file
    

    xorParam: int
    format_: XipDecoderStrategy

    fileDataCompressed: bytes # file content after decryption

    #for debug:
    unopenable_or_unimplemented: bool
    decryptedData: bytes
    uncryptedData: bytes

    def __init__(self, xipFile, baseOffset, xorKeyOffset, format_: XipDecoderStrategy):
        self.xorParam = xorKeyOffset
        self.baseOffset = baseOffset
        self.fileDescriptor = functions.japDeXor(xipFile[baseOffset: baseOffset + format_.fileHeaderLength()], xorKeyOffset , format_)

        a = self.fileDescriptor[0x0c:(0x0c + format_.fileNameLength())]
        a = a[ : a.find(b'\x00')]

        self.fileName = ""
        import os
        for enc in ["ascii", "shift-jis", "EUC-KR", "utf-8" ]:
            try:
                self.fileName = a.decode( enc )
                os.access(self.fileName, os.W_OK)
                break
            except UnicodeDecodeError:  # wrong encoding
                self.fileName = "" 
            except ValueError:          # windows impossible filename
                self.fileName = "" 
        if self.fileName == "":
            raise Exception("Could not decode the file name.")


        # TODO: final touch when it all works: remove magic numbers of the below lines.

        self.fileBlockSize , self.uncompressedSize = struct.unpack_from('<II', self.fileDescriptor, 0) 
        
        self.fileDataCompressedSize = self.fileBlockSize - 0x20  # what's 20h?

        self.cryptKeyIndex = self.fileDescriptor[0x118]
        self.crc32 = struct.unpack_from('<I', self.fileDescriptor, 0x110)[0]

        self.unknownA1 , self.unknownA2 = struct.unpack_from('<II', xipFile[self.baseOffset + 0x011C : (self.baseOffset + 0x011C + 8 )])


        # work in progress:
        sizeOfEncryptedData: int = 0x08 * 10

        padding:int = 0
        base = self.baseOffset + 0x011C + 8
        for i in range(1,10):
            a = xipFile[ base + padding : base + padding + i*4 ]
            if a == b"\x00\x00\x00\x00":    # TODO: what happens here?
                padding += 4
            else:
                break

        if padding != 0:
            from myBytes import printableBytes as pb
            logging.debug(f"{padding=} ; {pb(self.unknown3)=}")
            self.unopenable_or_unimplemented = True  
            return
        else:
            self.unopenable_or_unimplemented = False

        self.baseOffset += padding  # TODO remove this hack


        # shuffling algorithm part:
        try: 
            # TODO : this is only one of the many possible shufflings
            cryptChunk: bytes = xipFile[self.baseOffset + 0x011C + 8 : (self.baseOffset + 0x011C + 8 + sizeOfEncryptedData)]
            self.decryptedData = xipRsa(cryptChunk[:0x10], self.cryptKeyIndex) + cryptChunk[0x10:0x14] + xipRsa(cryptChunk[0x18:0x20], self.cryptKeyIndex+3) \
                + cryptChunk[0x20:0x24] + xipRsa(cryptChunk[0x28:0x50], self.cryptKeyIndex+5)
        except Exception as e:
            self.unopenable_or_unimplemented |= True # WIP
            return
            
        offset1 = baseOffset + 0x011C + 8 + sizeOfEncryptedData
        sizeRest = self.fileDataCompressedSize - 8 - 48
        if sizeRest > 0:
            self.uncryptedData = xipFile[offset1:offset1 + sizeRest]
        else:
            self.uncryptedData = bytes()

        self.fileDataCompressed = self.decryptedData + self.uncryptedData

    @property
    def unknown1(self):
        return  self.fileDescriptor[0x8 : 0x0c]     # 4 bytes, doesnt affect shuffling.

    @property
    def unknown2(self):
        return  self.fileDescriptor[0x114 : 0x118]  # 4 bytes, doesnt affect shuffling.
    
    @property
    def unknown3(self):
        return self.fileDescriptor[0x119 : 0x11c ]   # 3 bytes , affects shuffling algorithm.  always xx 00 00 ?


def openXip(name:str):
    with open(name, "rb") as xipFile:
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


    offsetSecretA: bytes = xipFile[4:5]+xipFile[6:7]+xipFile[8:9]+xipFile[11:12]
    offsetSecretA = struct.unpack_from('<I', offsetSecretA)[0]
    secretASkipSize = xipFile[9:10] + xipFile[7:8]
    secretASkipSize = struct.unpack_from('<H', secretASkipSize)[0]

    secretA = xipFile[offsetSecretA:int(offsetSecretA)+24]
    if type(xipDecoder) == xipDecoder_strategy.Xip3Decoder:
        ... # TODO add 0x98989898 step
        raise NotImplementedError("Not implemented yet." )
    secretA = xipRsa(secretA,0x0c)

    fileOffset : int
    numberOfFiles : int
    _ , fileOffset , numberOfFiles , checksumAData , _ = struct.unpack( '<H I I B B', secretA)

    functions.checksumA(fileOffset&0xff,numberOfFiles&0xff,checksumAData)

    files : List[PackagedFile] = []
    for fileNumber in range(numberOfFiles):
        if fileOffset == offsetSecretA:
            fileOffset += secretASkipSize
        pf = PackagedFile(xipFile, fileOffset, (numberOfFiles - fileNumber), xipDecoder)
        if pf.unopenable_or_unimplemented==True:
            fileOffset += xipDecoder.fileHeaderLength() + pf.fileBlockSize
            continue
        files.append(pf)

        logging.debug(pf.fileName)   

        dataout : bytes = bytes()
        
        from myBytes import printableBytes as pb
        #logging.debug(f"{pprint({a: b for a, b in vars(pf).items() if a in ['unknown1', 'unknown2', 'unknown3', 'unknownA1' , 'unknownA2' , 'xorParam', 'cryptKeyIndex']})}")
        #logging.debug(f"{pb(pf.unknown1)=}")
        #logging.debug(f"{pb(pf.unknown2)=}")
        #logging.debug(f"{pb(pf.unknown3)=}")        

        import lzo
        try:
            # unfortunately, the line below could suddenly crash python.exe because it's a C dll which will crash if the output buffer allocated (for the expected decompressed size) gets overflowed (because of a badly formed data) , even in a try-except block.
            dataout=lzo.decompress(pf.fileDataCompressed  , False, pf.uncompressedSize,  algorithm="LZO1X")
        except Exception as e:
            print("Decompression failed")


        if extractFiles := True :
            if dataout != bytes():
                
                # additonal decryption for some file types
                if len(pf.fileName.split("\\")[-1]) > 3:
                    extension: str = pf.fileName.split("\\")[-1][-4:]
                    if extension in xipDecoder.maskedFileTypes_ConfigFile():
                        dataout = functions.deXorTxt(dataout)
                    elif extension in xipDecoder.maskedFileTypes_VisualClip():
                        dataout = functions.deXorVisualClip(dataout)

                # make the folder structure
                path = pf.fileName.split("\\")
                if len(path) > 1:
                    folder = path[:-1]
                    folder = "\\".join(folder)
                    if "outFiles" not in os.listdir():
                        os.makedirs("./outFiles")
                    os.makedirs(f"./outFiles/{folder}", exist_ok=True)
                
                with open("./outFiles/" + pf.fileName.replace('\\','/') , "wb") as file:
                    file.write(dataout)
        
        fileOffset += xipDecoder.fileHeaderLength() + pf.fileBlockSize

    return files


def main(fileName : Optional[str] = None):
    if fileName is None:
        fileName = "System.pak"
    logging.basicConfig(level=logging.DEBUG)
    openXip(fileName)

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else None)

