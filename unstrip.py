#!/usr/bin/env python3
import shutil
import pwn
from pwn import log, ELF, libcdb
import argparse
import os
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description="Unstrip libc and patches the binary",
        add_help=False
    )
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("-f", "--force", action="store_true", help="Force overwrite the patched binary")
    parser.add_argument("--help", action="help", help="Show this help message and exit")

    return parser.parse_args()

def find_libc():
    libc_current_dir = os.path.join(os.getcwd(), "libc.so.6")
    if os.path.exists(libc_current_dir):
        return libc_current_dir
    return None

args = parse_args()
og_binary = "." + args.binary + ".bak"

libc_path = find_libc()
if not libc_path:
    log.error("Error: libc.so.6 not found")
    sys.exit(1)

is_patched = os.path.exists(os.path.join(os.getcwd(), og_binary))
if is_patched and not args.force:
    log.error("Error: binary already patched")
    sys.exit(1)

libs_path = libcdb.download_libraries(libc_path=libc_path, unstrip=True)
log.info("Downloaded libraries to %s", libs_path)

# create a copy of the binary to a .bak
shutil.copyfile(args.binary, og_binary)
binary = ELF.patch_custom_libraries(args.binary, libs_path, create_copy=False)
log.success("Patched binary %s", binary)
