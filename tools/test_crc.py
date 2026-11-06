import unittest
from check_module_crc import compare,symvers
from elf_audit import ELF
class CRC(unittest.TestCase):
 def test_equal(self):self.assertEqual(compare({'symbol':1},{'symbol':1}),{'missing':[],'mismatched':[],'checked':1})
 def test_mismatch(self):self.assertEqual(compare({'symbol':1},{'symbol':2})['mismatched'],['symbol'])
 def test_missing(self):self.assertEqual(compare({}, {'symbol':1})['missing'],['symbol'])
 def test_parse(self):self.assertEqual(symvers('0x123 symbol module EXPORT_SYMBOL'),{'symbol':0x123})
 def test_malformed(self):
  for text in ['broken','oops symbol module EXPORT_SYMBOL','0x123 symbol module EXPORT_SYMBOL\n0x123 symbol module EXPORT_SYMBOL']:
   with self.assertRaises(ValueError):symvers(text)
 def test_reject_input(self):
  with self.assertRaises(ValueError):ELF(b'not an ELF')
