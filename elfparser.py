from struct import pack,unpack
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from capstone import *
from capstone.x86_const import *
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
md32.detail = True
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
md64.detail = True

class ELF:
	def __init__(self,f):
		elf = ELFFile(f)
		if elf.get_machine_arch() == 'x64':
			self.bit = 64
		elif elf.get_machine_arch() == 'x86':
			self.bit = 32
		self.text = elf.get_section_by_name('.text').data()
		self.text_addr = elf.get_section_by_name('.text').header['sh_addr']
		dynsym = elf.get_section_by_name('.dynsym')

		dynsym_list = [0]
		if self.bit == 64:
			relplt = elf.get_section_by_name('.rela.plt')
		elif self.bit == 32:
			relplt = elf.get_section_by_name('.rel.plt')
		relpltdata = relplt.data()
		for x in range(0,len(relpltdata),relplt.header['sh_entsize']):
			tmp = relpltdata[x:x+relplt.header['sh_entsize']]
			if self.bit == 64:
				_,_,num,_ = unpack('QIIQ',tmp)
			elif self.bit == 32:
				_,num = unpack('II',tmp)
				num = num >> 8
			dynsym_list.append(num)

		c = 0
		for sym in dynsym.iter_symbols():
			if c in dynsym_list:
				dynsym_list[dynsym_list.index(c)] = sym.name
			c+=1

		got_plt = elf.get_section_by_name('.got.plt')
		got_plt_data = got_plt.data()
		plt = elf.get_section_by_name('.plt')
		plt_data = plt.data()
		self.funcs = {}

		for n in range(0,len(plt_data),16):
			tmp = n + plt.header['sh_addr']
			self.funcs[tmp] = dynsym_list[n/16]
			print dynsym_list[n/16]

		before = None
		if self.bit == 32:
			for i in md32.disasm(self.text,self.text_addr):
				if i and i.mnemonic == 'call' and i.operands[0].imm in self.funcs and self.funcs[i.operands[0].imm] == '__libc_start_main':
					self.ep = before.operands[0].imm
					break
				before = i

		elif self.bit == 64:
			for i in md64.disasm(self.text,self.text_addr):
				if i and i.mnemonic == 'call' and i.operands[0].imm in self.funcs and self.funcs[i.operands[0].imm] == '__libc_start_main':
					self.ep = before.operands[1].imm
					break
				before = i
		f.close()


if __name__ == '__main__':
	f = open(TESTFILE,'rb')
	elf = ELF(f)