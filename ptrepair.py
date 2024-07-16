import glob
import pathlib, sys

# this is to fix .pt files made by ptsearch.py that miss 4 zeroes at the end

def repair_pt(filename):    
    name = pathlib.Path(filename).stem
    with open( filename , "rb") as f:
        content = f.read()
        length = len(content)
        last_ez = content.find(b"EZTR", length - 0x94 )
    if last_ez == -1:
        print (f"{name} is ok")
        return
    elif last_ez != length - 0x4e :
        with open( filename , "ab") as f:
            zeros_to_add = last_ez - (length - 0x4e)
            for _ in range(zeros_to_add):
                f.write(b"\x00")
        print (f"{name} has been repaired")
    else:
        print (f"{name} is ok")

if __name__ == "__main__":
    # Use glob to expand wildcard patterns
    file_list = []
    for pattern in sys.argv[1:]:
        file_list.extend(glob.glob(pattern))

    # Process each file
    for filename in file_list:
        repair_pt(filename)