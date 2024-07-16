import pstats, logging, struct, sys, bcolors
from typing import Any, Dict, Final, List, Optional
import etcXorers
import xipFormatStrategy
from xipFormatStrategy import XipFormatStrategy
import os, sys, pathlib
from rsaDecryptor import WrongKeysError
from fileBlock import FileBlock

def extract(*args, **kwargs):
    # there's no indication if a pak uses the chinese keys or not (which are less popular), so we do this simple wrapper temporarily.
    try:
        extract_(*args, **kwargs)
    except WrongKeysError:
        try:
            extract_( *args, chineseVersion = True, **kwargs)
        except :
            print(f"{bcolors.ERR} file/key error with '{args[0]}'{bcolors.ENDC}")


def extract_(pakPath:str , enable_extractFiles: bool = True , enable_listFiles:bool = False, outSubfolder:str = "", chineseVersion:bool = False, **kwargs):

    pakFileName : Final = pathlib.Path(pakPath).name
    if kwargs.get("noIndividualFoldersParam") is not True:
        outSubfolder = "./outFiles/" + pakFileName + "/"
    else:
        outSubfolder = "./outFiles/"

    with open(pakPath, "rb") as xipFile:
        xipFile=bytes(xipFile.read())
        
    if xipFile[0:3] != b"XIP":
        raise Exception("Not a valid XIP file.")
    
    xipDecoder : XipFormatStrategy
    
    if xipFile[3:4] == b"2":
        if chineseVersion:
            xipDecoder = xipFormatStrategy.Xip2ChDecoder()
        else:
            xipDecoder = xipFormatStrategy.Xip2Decoder()
    elif xipFile[3:4] == b"3":
        xipDecoder = xipFormatStrategy.Xip3Decoder()
    else:
        raise Exception("Not a compatible XIP file.")
    
    if xipDecoder.environment_ok == False:
        for key in xipDecoder.REQUIRED_KEYS:
            if key not in os.listdir("./keyFiles"):
                raise Exception(f"Can't execute extractor, missing key file: {key}")
        xipDecoder.__class__.environment_ok = True

    # 00 13 fb 3f

    offsetSecretA: bytes = xipFile[4:5]+xipFile[6:7]+xipFile[8:9]+xipFile[11:12]
    offsetSecretA = struct.unpack_from('<I', offsetSecretA)[0]
    secretASkipSize = xipFile[9:10] + xipFile[7:8]
    secretASkipSize = struct.unpack_from('<H', secretASkipSize)[0]

    secretA = bytearray(xipFile[offsetSecretA:int(offsetSecretA)+24])
    if isinstance(xipDecoder, xipFormatStrategy.Xip3Decoder):
        s04 = (struct.unpack_from('<I', secretA[0:4])[0])
        secretA[0:4] = (0x98989898 ^ secretASkipSize ^ (struct.unpack_from('<I', secretA[0:4])[0])).to_bytes(4, "little")
        #secretA[0:4] = 40 25 7f cb
        secretA[0x10:0x14] = ( (struct.unpack_from('<I', secretA[0x10:0x14])[0]) ^ s04 ).to_bytes(4, "little")
        #secretA == bytearray(b'@%\x7f\xcb\xd4\xd4\x1c\x00\x00\x00\x13\x00\x00\x00\x00\x00\x88\xcd\xd9\xe6\xb5i\x17\x00')
        assert secretASkipSize == 0x18
    
    try:
        secretA = xipDecoder.xipRsaDecrypt(secretA,0x0c)
    except Exception as e:
        raise WrongKeysError()

    fileOffset : int
    numberOfFiles : int
    _ , fileOffset , numberOfFiles , checksumAData , _ = struct.unpack( '<H I I B B', secretA)

    if fileOffset > 0x3000 or numberOfFiles > 10000:
        raise WrongKeysError()

    etcXorers.checksumA(fileOffset&0xff,numberOfFiles&0xff,checksumAData)

    files : List[FileBlock] = []
    for fileNumber in range(numberOfFiles):
        if fileOffset == offsetSecretA:
            fileOffset += secretASkipSize
        fb = FileBlock(xipFile, fileOffset, (numberOfFiles - fileNumber), xipDecoder, fileNumber)
        files.append(fb)
        fileOffset += xipDecoder.FILE_HEADER_LENGTH + fb.fileBlockSize
        if not fb.noErrors :
            logging.debug(f"{bcolors.ERR}Parsing failed for a file{bcolors.ENDC}")            
            continue
        #logging.debug(pf.fileName)   

    if enable_listFiles:
        for fb in files:
            print(fb.fileName)

    if enable_extractFiles :
        pathsToMake = set()
        for fb in files:
            # make folder structures before extracting
            path = fb.fileName.split("\\")
            if any( [ p in [".", ".."] for p in path ] ):
                print(f"This filename/path is not supported for security reasons: {fb.fileName}") # this is not optimal
                continue
            if len(path) > 1:
                folder = path[:-1]
                folder = "/".join(folder)
                pathsToMake.add(f"{outSubfolder}{folder}")            
        
        for path in pathsToMake:
            os.makedirs(path, exist_ok=True)

        i: int = 0
        for fb in files:
            try:
                if not fb.noErrors :
                    print(f"\n{bcolors.ERR}Exception when parsing '{fb.fileName}'{bcolors.ENDC}")
                else:
                    result = fb.extractFile()
                    finalPath = (outSubfolder) + fb.fileName.replace('\\','/')
                    
                    #os.access( os.path.dirname(finalPath), os.W_OK) # this is to check if the path is valid

                    # check if file already exists
                    if os.path.exists(finalPath):
                        ...
                        #print(f"\n{bcolors.WARN}File '{fb.fileName}' already exists.{bcolors.ENDC}")
                    with open( finalPath, "wb") as file:
                        file.write(result["finalData"])

                    if not result["crcOk"]:
                        print(f"{bcolors.ERR}CRC32 check failed for '{fb.fileName}'{bcolors.ENDC}")
                    i += 1
                    print(f"\r{i}/{len(files)} files completed.", end="", flush=True)

            except Exception as e:
                print(f"\n{bcolors.ERR}Exception when decompressing '{fb.fileName}'{bcolors.ENDC}")
                print(e)
        print("")


    print(f"Done {pakFileName}.")

    return files


if __name__ == "__main__":
    extract( "./inputFiles/System_Script.pak" )
