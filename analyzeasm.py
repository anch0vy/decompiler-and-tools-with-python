import re

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
		for n in self.funcs.keys():
			print 'function:',hex(n)
			length = self.funcs[n][0]
			stack = []
			reg = {}
			#reg[X86_REG_RAX] = [[X86_REG_AL,None],[X86_REG_AH,None],[X86_REG_AX,None],[X86_REG_EAX,None],[X86_REG_RAX,None]]
			code = self.text[n - self.text_addr:n - self.text_addr + length]
			if code.startswith('\x55\x89\xe5') or code.startswith('\x55\x48\x89\xe5'):
				#start with push bp, mov bp,sp
				if self.bit == 32:
					code = code[3:]
					n = n + 3
				else:
					code = code[4:]
					n = n + 4

			for i in self.md.disasm(code,n):				
				if i.mnemonic == 'sub':
					print i.operands[0]
					if i.operands[0].reg == X86_REG_RSP or i.operands[0].reg == X86_REG_ESP:
						stack = stack + [None] * (i.operands[1].imm / 4)
				
				# print "0x%x:\t%s\t%s" %(i.address , i.mnemonic, i.op_str),
				# print stack


	def checkrodata(self,addr):
		rodata_start_addr = self.elf.rodata.header['sh_addr']
		addr = addr - rodata_start_addr
		found = re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", self.elf.rodata_data[addr:])
		if len(found) > 0:
			if self.elf.rodata_data.index(found[0]) == addr:
				return found[0]
		return None

if __name__ == '__main__':
	q = decompile('a.out_strip')
	print '[*]EP:',hex(q.ep)
	q.findFunction()
	q.asm2ir()
	exit()
	print '[*]found function num:',len(q.funcs.keys())
	print '[*]addr_start addr_end function_length analyzed_flag'
	for n in q.funcs.keys():
		print hex(n), hex(n+q.funcs[n][0]),q.funcs[n]

'''
memo

x86
55 89 E5 -> push ebp, mov ebp,esp
C9 C3 -> leave,ret

x64
55 48 89 E5 -> push rbp, mov rbp,rsp
C9 C3 -> leave,ret

rax:eax:ax:ah:al


'''