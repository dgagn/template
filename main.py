#!/usr/bin/env python3

import os
import stat
import sys
import argparse
from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from elftools.common.exceptions import ELFError

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate pwntools exploit template with real argument parsing.",
        add_help=False
    )
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing file (default: False)")
    parser.add_argument("--host", default="localhost", help="Remote host (default: localhost)")
    parser.add_argument("--port", type=int, default=443, help="Remote port (default: 1337)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL (default: False)")
    parser.add_argument("-p", "--stdout", action="store_true", help="Use stdout (default: False)")
    parser.add_argument("--file", default="ape.py", help="Output file (default: ape.py)")
    parser.add_argument("--help", action="help", help="Show this help message and exit")

    return parser.parse_args()

args = parse_args()

binary = args.binary
file = args.file
stdout = args.stdout

if not os.path.exists(binary):
    print(f"Error: {binary} not found", file=sys.stderr)
    sys.exit(1)

try:
   ctx.binary = ELF(binary, checksec=False)
except ELFError:
    pass

checksec_binary = ctx.binary.checksec(color=False).splitlines()

arch = ctx.binary.arch + "-" + str(ctx.binary.bits) + "-" + ctx.binary.endian
comment = f"# Arch:       {arch}\n"
for line in checksec_binary:
    comment += f"# {line}\n"

comment = comment.strip()
template = f'''
#!/usr/bin/env python3
from pwn import *

{comment}

elf = context.binary = ELF('{binary}')
libc = elf.libc

context.log_level = 'info'
context.aslr = True

def start():
    host = args.HOST or '{args.host}'
    port = int(args.PORT or {args.port})
    if args.REMOTE:
        return remote(host, port{", ssl=True" if args.ssl else ""})
    io = elf.process()
    if args.GDB:
        gdb.attach(io, gdbscript)
    return io


gdbscript = \'\'\'
continue
\'\'\'


io = start()

io.interactive()
'''.strip()

if stdout:
    print(template)
else:
    if os.path.exists(file):
        print(f"Error: {file} already exists", file=sys.stderr)
        sys.exit(1)
    with open(file, "w") as f:
        f.write(template)
    st = os.stat(file)
    os.chmod(file, st.st_mode | stat.S_IEXEC)
    print(f"Template saved to {file}")
