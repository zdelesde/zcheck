#!/usr/bin/env python3

import logging
import os
import hashlib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%Y-%m-%d-%H-%M-%S')

dirs = ["/"]
skip = "/root /home /var /tmp /dev /sys /proc /run /net /mnt /media".split()

def sha256_of_file(fn, bs=2**20):
    sha256 = hashlib.sha256()
    with open(fn, "rb") as fh:
        while True:
            buf = fh.read(bs)
            if not buf:
                break
            sha256.update(buf)
    return sha256.hexdigest()

def process_dir(d):
    with os.scandir(d) as entries:
        for entry in entries:
            row = [entry.path]
            st = os.lstat(entry.path)
            if entry.is_symlink():
                row.append("L")
                row.append(oct(st.st_mode)[-4:])
                row.append(st.st_uid)
                row.append(st.st_gid)
                row.append(os.readlink(entry.path))
            elif entry.is_file():
                row.append("F")
                row.append(oct(st.st_mode)[-4:])
                row.append(st.st_uid)
                row.append(st.st_gid)
                row.append(sha256_of_file(entry.path))

            elif entry.is_dir():
                row.append("D")
                row.append(oct(st.st_mode)[-4:])
                row.append(st.st_uid)
                row.append(st.st_gid)
                dirs.append(entry.path)
            else:
                row.append("?")
                row.append(oct(st.st_mode)[-4:])
                row.append(st.st_uid)
                row.append(st.st_gid)
                
            print("\t".join(map(str, row)))

logging.info("starting run")

while len(dirs) > 0:
    d = dirs.pop()
    if d not in skip:
        process_dir(d)

logging.info("done")