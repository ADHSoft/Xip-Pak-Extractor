import io
import os
from typing import Dict, List
import zlib
import bcolors
import etcXorers, pathlib

ASK_TO_OVERWRITE = False
REMOVE_MP_SUBFILES_AFTER_EXTRACTING= True

'''
Extractor for file format used in:
DMP 1;2;Fever;Hot tunes
'''
def extractMp( mpPathAndName = "./inputFiles/portableMPs/"+"all.mp", baseOutputFolderParam = "./outFiles/", firstCall = True , mainPakName = ""):
    # baseOutputFolderParam must end with /

    mpFileName = pathlib.Path(mpPathAndName).name
    if firstCall:
        mainPakName = mpFileName
    # mpPath = pathlib.Path(mpPathAndName).parent.as_posix() + "/"
   
    with open(f"{mpPathAndName}", "rb") as f:
        if f.read(3) != b"MP0":
            raise Exception("Not a valid MP file")
        unk1 = f.read(1)
        if unk1 != b"2":
            ...
            #raise NotImplementedError("not 'MP02'")
        compressed = f.read(1)
        if compressed == b"\x00":
            compressed = False
        elif compressed == b"\x01":
            compressed = True
        else:
            raise NotImplementedError("Unknown compression type")
                
        
        f.read(0x03)
        total_num_files = int.from_bytes(f.read(4), "little")
        inputBuffer : io.BytesIO
        mpUncompressedSize = int.from_bytes(f.read(4), "little")
        if compressed:            
            decompressedData = b""

            while True:
                nextCompressedBlockSize = int.from_bytes(f.read(4), "little")
                if nextCompressedBlockSize == 0:
                    break
                decompressedData +=  zlib.decompress(f.read(nextCompressedBlockSize), bufsize=0x20000)
                
            inputBuffer = io.BytesIO(decompressedData)
           
        else:            
            inputBuffer = io.BytesIO(f.read())
        
        files : List[Dict] = []
        for file_num in range(total_num_files):
            header = inputBuffer.read(0x8c)
            header =  etcXorers.japUnXor_(header, file_num, 0x8c)   # unXor header
            header = header[:4] + etcXorers.japUnXor_(header[4:], 0, 0x80,True) + header[-8:] # unXor filename
            files.append({"name":header[4:-8].split(b"\x00")[0].decode("EUC-KR") , "hash":int.from_bytes(header[:4], "little") , "offset":int.from_bytes(header[-8:-4], "little") , "size":int.from_bytes(header[-4:], "little")})
            # make folder structure
            outFileName = files[-1]['name'].split("/")[-1]
            outPath = f"{baseOutputFolderParam}{mpFileName if firstCall else mainPakName}/{ '/'.join(files[-1]['name'].split('/')[:-1]) }"
            os.makedirs(outPath, exist_ok=True)
            if os.path.exists(f"{outPath}/{outFileName}"):
                msg=f"{bcolors.WARN}Warning: {outPath}/{outFileName} already exists. {'Press [o] + [enter] to overwrite or [enter] to not.' if ASK_TO_OVERWRITE else 'Overwriting.'}  mpFile={mpPathAndName}{bcolors.ENDC}"
                if ASK_TO_OVERWRITE:                    
                    if input(msg).lower != "o":
                        continue
                    print("overwritten.")
                else:
                    print(msg)
            returnPos = inputBuffer.tell()
            with open(f"{outPath}/{outFileName}", "wb") as f2:                
                inputBuffer.seek(files[-1]["offset"])
                f2.write(inputBuffer.read(files[-1]["size"]))
            inputBuffer.seek(returnPos)
            print(f"Extracted {files[-1]['name']}")
        print(f"extracted {total_num_files} files from {mpFileName}")

    # recursively extract the .mp files contained inside the already extracted .mp files
    if firstCall:
        while True:
            mp_files = []
            for root, _, files_ in os.walk(f"{baseOutputFolderParam}{mainPakName}"):
                for file_ in files_:
                    if file_.endswith('.mp'):
                        relative_path = os.path.relpath(os.path.join(root, file_), f"{baseOutputFolderParam}{mainPakName}")
                        mp_files.append(relative_path)
            if len(mp_files) == 0:
                break
            for mp_rel_filename in mp_files:
                # relativeFolder = os.path.dirname(mp_rel_filename)
                extractMp(f"{baseOutputFolderParam}{mpFileName}/{mp_rel_filename}", baseOutputFolderParam=baseOutputFolderParam , firstCall=False, mainPakName=mpFileName)
                # something has to be done with the extracted mp file, if not, it will loop forever.
                if REMOVE_MP_SUBFILES_AFTER_EXTRACTING:
                    # delete it
                    os.remove(f"{baseOutputFolderParam}{mpFileName}/{mp_rel_filename}")
                else:
                    # rename it
                    os.rename(f"{baseOutputFolderParam}{mpFileName}/{mp_rel_filename}", f"{baseOutputFolderParam}{mpFileName}/{mp_rel_filename}_")

    print(f"Finished extracting {mpFileName} and its .mp subfiles.")

def extractEveryMp(inputFolder = "./"):
    #inputFolder = "./inputFiles/"
    
    for mp in [a for a in os.listdir(inputFolder) if a.endswith(".mp")]:    # (non recursive)
        extractMp(f"{inputFolder}{mp}")

if __name__ == "__main__":
    #extractEveryMp("W:\\PSP_GAME\\USRDIR\\")
    extractEveryMp("./mpFiles/")