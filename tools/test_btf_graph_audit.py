import importlib.util, struct, unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('audit',Path(__file__).with_name('btf_graph_audit.py'))
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
def blob(records, strings=b'\0node\0next\0int\0x\0'):
    data=b''.join(struct.pack('<III',name,kind<<24|flags|n,value)+struct.pack('<'+'I'*len(words),*words) for name,kind,n,value,words,flags in records)
    return struct.pack('<HBBIIIII',0xeb9f,1,0,24,0,len(data),len(data),len(strings))+data+strings
def rec(name,kind,n,value,words=(),flags=0): return name,kind,n,value,words,flags
class Audit(unittest.TestCase):
    def test_recursive_id_permutation(self):
        old=a.graph(blob([rec(1,4,1,8,(6,2,0)),rec(0,2,0,1)]))
        new=a.graph(blob([rec(0,2,0,2),rec(1,4,1,8,(6,1,0))]))
        cs,_=a.partition([old,new]);self.assertEqual(cs[0][1],cs[1][2]);self.assertEqual(cs[0][2],cs[1][1])
    def test_deep_field_change_propagates(self):
        old=a.graph(blob([rec(1,4,1,8,(6,2,0)),rec(0,2,0,1)]))
        new=a.graph(blob([rec(1,4,1,8,(6,2,8)),rec(0,2,0,1)]))
        cs,_=a.partition([old,new]);self.assertNotEqual(cs[0][2],cs[1][2])
    def test_string_offsets_are_normalized(self):
        g1=a.graph(blob([rec(11,1,0,4,(0x1000020,))]))
        g2=a.graph(blob([rec(1,1,0,4,(0x1000020,))],b'\0int\0'))
        cs,_=a.partition([g1,g2]);self.assertEqual(cs[0][1],cs[1][1])
    def test_scalar_metadata_changes(self):
        pairs=[(rec(11,1,0,4,(32,)),rec(11,1,0,4,(0x1000020,))),
               (rec(0,3,0,0,(0,0,8)),rec(0,3,0,0,(0,0,9))),
               (rec(1,6,1,4,(15,1)),rec(1,6,1,4,(15,2))),
               (rec(1,19,1,8,(15,1,0)),rec(1,19,1,8,(15,1,1))),
               (rec(0,13,1,0,(15,0)),rec(0,13,1,0,(6,0))),
               (rec(1,4,1,8,(6,0,0)),rec(1,4,1,8,(6,0,0),1<<31)),
               (rec(1,17,0,0,(0,)),rec(1,17,0,0,(1,))),
               (rec(1,15,1,8,(0,0,4)),rec(1,15,1,8,(0,4,4)))]
        for x,y in pairs:
            cs,_=a.partition([a.graph(blob([x])),a.graph(blob([y]))]);self.assertNotEqual(cs[0][1],cs[1][1])
    def test_duplicate_candidates_not_unique(self):
        g1=a.graph(blob([rec(0,2,0,0)]));g2=a.graph(blob([rec(0,2,0,0),rec(0,2,0,0)]))
        cs,_=a.partition([g1,g2]);self.assertEqual(sum(c==cs[0][1] for c in cs[1]),2)
    def test_bad_inputs(self):
        for data in [b'',blob([rec(0,2,0,99)]),blob([rec(999,2,0,0)]),blob([rec(0,2,0,0)])[:-1]]:
            with self.assertRaises(ValueError): a.graph(data)
if __name__=='__main__': unittest.main()
