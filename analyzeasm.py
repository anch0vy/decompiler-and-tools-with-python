from type import REG
from elfparser import ELF
from capstone import *
from capstone.x86_const import *

class decompile:
	def __init__(self,fileName,arch='linux'):
		if arch == 'linux':
			self.elf = ELF(open(fileName,'rb'))
			self.text = self.elf.text
			self.text_addr = self.elf.text_addr
			self.ep = self.elf.ep
			self.extrn_funcs = self.elf.funcs
			self.bit = self.elf.bit
			self.endfuncion = ['__assert_fail','abort','_exit','__cxa_atexit','exit','__stack_chk_fail']
		else:
			raise Exception('unsupported arch')
		self.funcs = {} #self.funcs[function_addr_start]   = [len, function_analyzed]
		self.funcs[self.ep] = [-1,False]

	def findFunction(self):
		if self.bit == 32:
			self.md = Cs(CS_ARCH_X86, CS_MODE_32)
			self.md.detail = True
		elif self.bit == 64:
			self.md = Cs(CS_ARCH_X86, CS_MODE_64)
			self.md.detail = True
		while not all(map(lambda x:x[1],self.funcs.values())):
			for addr in self.funcs.keys():
				if addr>self.text_addr + len(self.text) or addr < self.text_addr:
					del(self.funcs[addr])
			for func_addr_start , (length,function_analyzed) in self.funcs.items():
				if not function_analyzed:
					break
			addrs = {} #for save read instruct
			jmps = []
			failend = []
			for i in self.md.disasm(self.text[func_addr_start - self.text_addr:],func_addr_start):
				self.funcs[func_addr_start] = [-1 , -1]
				addrs[i.address] = i

				if i.group(X86_GRP_JUMP):
					jmpop = i.operands[0]
					jmpaddr = i.operands[0].imm
					if jmpop.type == X86_OP_IMM:
						if jmpaddr in self.extrn_funcs:
							if all(map(lambda x:x in addrs , jmps)):
								self.funcs[func_addr_start] = [i.address - func_addr_start + i.size , True]
								break
							else:
								failend.append(i.address)

						elif jmpaddr in addrs and len(failend) > 0 and i.mnemonic=='jmp':
							if all(map(lambda x:x<=i.address,jmps)):
								self.funcs[func_addr_start] = [i.address - func_addr_start + i.size , True]
								break

						else:
							jmps.append(jmpaddr)


				elif i.group(X86_GRP_CALL):
					callop = i.operands[0]
					calladdr = callop.imm
					if callop.type == X86_OP_IMM and calladdr not in self.extrn_funcs and calladdr not in self.funcs:
						self.funcs[calladdr] = [-1,False]

					if calladdr in self.extrn_funcs and self.extrn_funcs[calladdr] in self.endfuncion:
						if all(map(lambda x:x in addrs , jmps)):
							self.funcs[func_addr_start] = [i.address - func_addr_start + i.size , True]
							break
						else:
							failend.append(i.address)
						

				elif i.group(X86_GRP_RET):
					if all(map(lambda x:x in addrs , jmps)):
						#end of function
						self.funcs[func_addr_start] = [i.address - func_addr_start + i.size , True]
						break
					else:
						failend.append(i.address)
	def asm2ir(self):
		pass


if __name__ == '__main__':
	q = decompile('a.out_strip')
	print '[*]EP:',hex(q.ep)
	q.findFunction()
	print '[*]found function num:',len(q.funcs.keys())
	print '[*]addr_start addr_end function_length analyzed_flag'
	for n in q.funcs.keys():
		print hex(n), hex(n+q.funcs[n][0]),q.funcs[n]
	