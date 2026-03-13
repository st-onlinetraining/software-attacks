import argparse

parser = argparse.ArgumentParser(prog='gadget.py', description='find ROP gadgets in disassembly file')
parser.add_argument('strings', nargs='*', type=str, help='strings to search')
parser.add_argument('-filename', '-f', default='wsf/tutorial1/app/app.txt', help='disassembly file')
parser.add_argument('-display', '-d', type=int, default=1, help='number of instructions to display')

args = parser.parse_args()

lines = []
gadgets = []

with open(args.filename, 'rt') as f:
    for line in f.readlines():
        if line.startswith('  0x'):  
            lines.append(line)
        if line.startswith(' '): # gcc
            lines.append(line)


for i in range(len(lines)):
    line = lines[i]
    if 'POP' in line.upper() and 'PC' in line.upper():
        gadgets.append(''.join(lines[i-args.display+d+1] for d in range(args.display)))

for g in gadgets:
    found = True
    for s in args.strings:
        if s not in g:
            found = False
    if found:
        print(g) 
