#!/usr/bin/env python3
"""Offline exact-label BTF graph bisimulation audit; never rewrites BTF or modules.
Matching is stricter than ABI compatibility (names/linkage/metadata are retained),
but bisimulation is not a proof of graph identity, runtime safety or relocation.
"""
import argparse, collections, hashlib, importlib.util, json, struct
from pathlib import Path

REF_VALUE = {2, 8, 9, 10, 11, 12, 13, 14, 17, 18}

def graph(data):
    if len(data) < 24:
        raise ValueError('Truncated header')
    magic, version, flags, hdr, to, tl, so, sl = struct.unpack_from('<HBBIIIII', data)
    if (magic, version, flags) != (0xeb9f, 1, 0) or hdr < 24 or hdr + max(to+tl, so+sl) > len(data):
        raise ValueError('Invalid header')
    strings = data[hdr+so:hdr+so+sl]
    def name(off):
        if off >= len(strings):
            raise ValueError('Invalid string offset')
        end = strings.find(b'\0', off)
        if end < 0:
            raise ValueError('Unterminated string')
        return strings[off:end]
    nodes = [((0, 0, b'void', ()), ())]
    pos, end = hdr+to, hdr+to+tl
    while pos < end:
        if pos+12 > end:
            raise ValueError('Truncated type')
        no, info, value = struct.unpack_from('<III', data, pos)
        kind, n = (info >> 24) & 31, info & 65535
        counts = {1:1, 2:0, 3:3, 4:3*n, 5:3*n, 6:2*n, 7:0, 8:0, 9:0, 10:0, 11:0, 12:0, 13:2*n, 14:1, 15:3*n, 16:0, 17:1, 18:0, 19:3*n}
        if kind not in counts or pos+12+counts[kind]*4 > end:
            raise ValueError('Invalid kind/length')
        words = list(struct.unpack_from('<'+'I'*counts[kind], data, pos+12))
        ref_positions, name_positions = [], []
        if kind == 3: ref_positions = [0, 1]
        if kind in (4, 5):
            name_positions = list(range(0, 3*n, 3)); ref_positions = list(range(1, 3*n, 3))
        if kind == 6: name_positions = list(range(0, 2*n, 2))
        if kind == 13:
            name_positions = list(range(0, 2*n, 2)); ref_positions = list(range(1, 2*n, 2))
        if kind == 15: ref_positions = list(range(0, 3*n, 3))
        if kind == 19: name_positions = list(range(0, 3*n, 3))
        refs = [value] if kind in REF_VALUE else []
        for i in ref_positions:
            refs.append(words[i]); words[i] = None
        for i in name_positions: words[i] = name(words[i])
        nodes.append(((info, None if kind in REF_VALUE else value, name(no), tuple(words)), tuple(refs)))
        pos += 12+counts[kind]*4
    if any(r >= len(nodes) for _, refs in nodes for r in refs):
        raise ValueError('Out-of-range base reference')
    return nodes

def partition(graphs):
    nodes = []; offsets = []
    for g in graphs:
        offset = len(nodes); offsets.append(offset)
        nodes.extend((label, tuple(r+offset for r in refs)) for label, refs in g)
    def intern(keys):
        table = {}; result = []
        for key in keys:
            if key not in table: table[key] = len(table)
            result.append(table[key])
        return result, len(table)
    colors, count = intern(label for label, _ in nodes)
    history = [count]
    for iteration in range(len(nodes)+1):
        refined, new_count = intern((colors[i], tuple(colors[r] for r in refs)) for i, (_, refs) in enumerate(nodes))
        history.append(new_count); colors = refined
        if new_count == count:
            # Refinement includes prior color: no merging can hide a split.
            return [colors[o:o+len(g)] for o, g in zip(offsets, graphs)], history
        count = new_count
    raise RuntimeError('Partition did not converge')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('base',type=Path);p.add_argument('candidate',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists():p.error('Fresh output required')
    gs=[graph(x.read_bytes()) for x in (a.base,a.candidate)]
    colors,history=partition(gs);bycolor=collections.defaultdict(list)
    for i,c in enumerate(colors[1]):bycolor[c].append(i)
    matches=[bycolor[c] for c in colors[0]]
    report={'base_types':len(gs[0])-1,'candidate_types':len(gs[1])-1,'missing':sum(not m for m in matches[1:]),'ambiguous':sum(len(m)>1 for m in matches[1:]),'uniquely_mapped':sum(len(m)==1 for m in matches[1:]),'classes':history,'scope':'Exact-label bisimulation, not graph identity, relocation or runtime safety'}
    with a.output.open('x') as f:json.dump(report,f,indent=2)
    print(json.dumps(report));return bool(report['missing'] or report['ambiguous'])
if __name__=='__main__':raise SystemExit(main())
