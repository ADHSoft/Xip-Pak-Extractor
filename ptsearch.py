#v 1.0.1

import hashlib

def main():
    off = 0
    with (open('DJMax.DMP', 'rb')) as file_:
        file_ = file_.read()
        off=file_.find(b"PTFF", off+4)
        while off != -1:
            if file_[off+4:off+4+8] == (b"\x00"*8):
                off=file_.find(b"PTFF", off+4)
                continue
            num_tracks = int.from_bytes(file_[off+0x0c:off+0x0c+0x2], "little")
            endoff = off+4
            for _ in range(num_tracks):
                endoff=file_.find(b"EZTR", endoff+1 )
                if endoff == -1:
                    break
            if endoff == -1:
                break
            endoff+=0x4e

            fileout = file_[off:endoff]
            with open(f"{hashlib.md5(fileout).hexdigest()[:16]}.pt", "wb") as f:
                f.write(fileout)
            off=file_.find(b"PTFF", off+4)

if __name__ == '__main__':
    main()