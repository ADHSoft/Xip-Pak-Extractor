import os, hashlib, env
from typing import Dict, List

def main(**kwargs):
    # name, first bytes, length, md5, description
    keySignatures : Dict[str, List] = {
        "key1a.bin": [b"\x3D\x8E\x82\x3D", 0x800, "a6e4dbb2e181e653083c6d5ee623b044", "FDK key a"],
        "key1b.bin": [b"\x01\xA9\xD6\xB2", 0x800, "b305cb2ee7986b016eb1b81b110cf4c4", "FDK key b"],
        "key1c.bin": [b"\xC5\x00\x5B\x01\x00\x00", 0x800, "b2039ff0f38400038176616610e3a854", "FDK key c (used only in TR)"],
        "USB_16128_10.dat" : [b"\x34\x12\x01\x00", 0x80, "e547ac65c94f74df882f917e27234703", "USB key (TR)"],
        "key1a_ch.bin": [b"\xE7\xE3\x4F\xB1\x8D", 0x800, "6a4fba222fe8e192f4afe2c004eba6c6", "FDK key a (for Chinese client)"],
        "key1b_ch.bin": [b"\xF9\xCB\x59\xD5\xD9", 0x800, "e55e431103937d161fb08d263445cc60", "FDK key b (for Chinese client)"],}

    files = os.listdir("./")
    files = [f for f in files if f.count(".") != 0 and f.split(".")[-1] in ["exe", "dll", "ex_", "client"] and f != env.EXE_NAME ]

    if not os.path.exists("./keyFiles"):
        os.makedirs("./keyFiles")

    if test := False:
        existingKeys = []
    else:
        existingKeys = os.listdir("./keyFiles")

    for f in files:
        with open(f, "rb") as f:
            data = f.read()
            for key in (set(keySignatures.keys()) - set(existingKeys)):
                pos = -1
                pos = data.find(keySignatures[key][0], pos+1)
                while pos != -1:
                    content = data[pos:(pos+keySignatures[key][1])]
                    if hashlib.md5(content).hexdigest() == keySignatures[key][2]:
                        with open(f"./keyFiles/{key}", "wb") as keyFile:
                            keyFile.write( content )
                            print(f"Got a new key, {key} from {f.name} . ({keySignatures[key][3]})")
                        break
                    else:
                        #print(f"a part of {key} is in {f.name} .")
                        pos = data.find(keySignatures[key][0], pos+1)
    if len(files) == 0:
        print("No game executables were found to get the keys from ")

if __name__ == "__main__":
    main()