#!/usr/bin/env python3
"""Check resolved BTF IDs against ELF symbol names, accounting for sorted ID sets."""
import argparse,collections,hashlib,importlib.util,json,re,struct
from pathlib import Path
from btf_graph_audit import graph

def verify(path):
 data=path.read_bytes()
 if data[:6]!=b'\x7fELF\x02\x01':raise ValueError('ELF64 little endian required')
 off=struct.unpack_from('<Q',data,40)[0];entry,n,idx=struct.unpack_from('<HHH',data,58);hs=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*entry) for i in range(n)];ns=hs[idx];strings=data[ns[4]:ns[4]+ns[5]]
 def z(b,i):
  end=b.find(b'\0',i)
  if end<0:raise ValueError('Unterminated ELF string')
  return b[i:end].decode()
 sections={z(strings,h[0]):h for h in hs};btf=sections['.BTF'];g=graph(data[btf[4]:btf[4]+btf[5]])
 def read(addr,size):
  matches=[h for h in hs if h[1]!=8 and h[3]<=addr and addr+size<=h[3]+h[5]]
  if len(matches)!=1:raise ValueError('ELF address ambiguity')
  h=matches[0];i=h[4]+addr-h[3];return data[i:i+size]
 h=sections['.symtab'];st=hs[h[6]];names=data[st[4]:st[4]+st[5]];symbols=[]
 for pos in range(h[4],h[4]+h[5],h[9]):
  no,info,other,index,addr,size=struct.unpack_from('<IBBHQQ',data,pos);name=z(names,no)
  if name.startswith('__BTF_ID__'):symbols.append((name,addr,size))
 kinds={'struct':4,'union':5,'typedef':8,'func':12};entries=[];groups=[]
 for name,addr,size in symbols:
  m=re.fullmatch(r'__BTF_ID__(set8|set)__(.+)',name)
  if m:groups.append({'symbol':name,'addr':addr,'size':size,'stride':8 if m[1]=='set8' else 4,'header':8 if m[1]=='set8' else 4});continue
  m=re.fullmatch(r'__BTF_ID__(struct|union|typedef|func)__(.+)__\d+',name)
  if not m:raise ValueError('Unrecognized BTF ID symbol '+name)
  entries.append({'symbol':name,'addr':addr,'wanted':(kinds[m[1]],m[2])})
 def label(i):
  if not 0<i<len(g):raise ValueError('Invalid resolved ID '+str(i))
  l=g[i][0];return (l[0]>>24&31,l[2].decode())
 errors=[];seen=set();set_records=[]
 for group in groups:
  addr,size,header,stride=(group[k] for k in ('addr','size','header','stride'));count=struct.unpack('<I',read(addr,4))[0]
  if size!=header+count*stride:raise ValueError('ID set size mismatch '+group['symbol'])
  inside=[(i,e) for i,e in enumerate(entries) if addr+header<=e['addr']<addr+size]
  if len(inside)>count:raise ValueError('Too many ID set symbols')
  seen.update(i for i,e in inside);actual=[];ids=[];flagged=[]
  for j in range(count):
   raw=read(addr+header+j*stride,stride);bid=struct.unpack_from('<I',raw)[0];ids.append(bid);actual.append(label(bid) if bid else (0,'<unused>'));flagged.append([*actual[-1],struct.unpack_from('<I',raw,4)[0] if stride==8 else None])
  expected=[e['wanted'] for i,e in inside]+[(0,'<unused>')]*(count-len(inside))
  if collections.Counter(actual)!=collections.Counter(expected) or ids!=sorted(ids):errors.append(group['symbol'])
  set_records.append({'symbol':group['symbol'],'count':count,'members':[list(x) for x in actual],'flagged_members':flagged,'set_flags':struct.unpack('<I',read(addr+4,4))[0] if header==8 else None})
 for i,e in enumerate(entries):
  if i in seen:continue
  bid=struct.unpack('<I',read(e['addr'],4))[0]
  if label(bid)!=e['wanted']:errors.append(e['symbol'])
 return {'elf_sha256':hashlib.sha256(data).hexdigest(),'btf_sha256':hashlib.sha256(data[btf[4]:btf[4]+btf[5]]).hexdigest(),'individual_symbols':len(entries),'sets':len(groups),'standalone_ids':len(entries)-len(seen),'mismatches':errors,'set_records':set_records,'scope':'Resolved numeric IDs, expected kind/name and sorted set membership. No runtime BPF proof.'}
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('vmlinux',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('Fresh output required')
 r=verify(a.vmlinux);a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:v for k,v in r.items() if k!='set_records'},indent=2));raise SystemExit(bool(r['mismatches']))
