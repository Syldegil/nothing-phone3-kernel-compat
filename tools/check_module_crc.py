"""Compare module __versions imports against an explicitly supplied Module.symvers."""
import argparse,json
from pathlib import Path
from elf_audit import ELF

def symvers(text):
 result={}
 for line in text.splitlines():
  if not line.strip():continue
  fields=line.split()
  if len(fields)<4:raise ValueError('Malformed Module.symvers')
  crc=int(fields[0],16)
  if not 0<=crc<=0xffffffff or fields[1] in result:raise ValueError('Invalid or duplicate symbol')
  result[fields[1]]=crc
 return result

def compare(expected,imports):
 return {'missing':sorted(n for n in imports if n not in expected),'mismatched':sorted(n for n,c in imports.items() if n in expected and c!=expected[n]),'checked':len(imports)}

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--symvers',type=Path,required=True);p.add_argument('modules',type=Path,nargs='+');a=p.parse_args()
 expected=symvers(a.symvers.read_text());results=[]
 for f in a.modules:
  r=compare(expected,ELF(f.read_bytes()).versions());results.append(r)
 print(json.dumps({'modules':results,'scope':'Import CRC comparison only; not load/runtime or complete ABI proof'},indent=2))
 raise SystemExit(any(r['missing'] or r['mismatched'] or not r['checked'] for r in results))
