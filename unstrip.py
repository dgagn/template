#!/usr/bin/env python3
import pwn
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

libc_path = find_libc()
if not libc_path:
    print("Error: libc.so.6 not found", file=sys.stderr)
    sys.exit(1)

is_patched = os.path.exists(os.path.join(os.getcwd(), args.binary + ".patched"))
if is_patched and not args.force:
    print("Error: binary already patched", file=sys.stderr)
    sys.exit(1)

# redundant, but just in case
if is_patched and args.force:
    os.remove(args.binary + ".patched")

libs_path = pwn.libcdb.download_libraries(libc_path=libc_path, unstrip=True)
pwn.log.info("Downloaded libraries to %s", libs_path)

binary = pwn.ELF.patch_custom_libraries(args.binary, libs_path, create_copy=True, suffix=".patched")
pwn.log.success("Patched binary %s", binary)
