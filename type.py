from numpy import float32,float64
from struct import pack,unpack
from capstone.x86_const import *


# class REG:
# 	'''no plan'''
# 	def __init__(self,regname):
# 		self.v = 0
# 		self.name = regname

# 	def get(self,bit):
# 		return int(pack('>Q',self.v).encode('hex')[(64 - bit)/4:],16)

# 	def set(self,op,bit):
# 		self.v = self.v >> bit << bit
# 		self.v += op

# 	def add(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v += op
# 		self.set(v,bit)

# 	def sub(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v -= op
# 		self.set(v,bit)

# 	# def mul(self,op,bit = 64):
# 	# 	v = get(self.v,bit)
# 	# 	v *= op
# 	# 	self.set(v,bit)

# 	# def imul(self,op,bit = 64):
# 	# 	v = get(self.v,bit)
# 	# 	self.set(v,bit)

# 	def xor(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v ^= op
# 		self.set(v,bit)

# 	def and_(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v &= op
# 		self.set(v,bit)

# 	def or_(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v |= op
# 		self.set(v,bit)

# 	def mov(self,op,bit = 64):
# 		v = get(self.v,bit)
# 		v = op
# 		self.set(v,bit)

# class ST:
# 	def __init(self):
# 		self.v = 0

class var:
	'''for unknown value'''
	def __init__(self):
		self.v = None
		self.pointer = False
		self.base = None

class REG4IR:
	'''for saving reg info in asm -> ir function'''
	def __init__(self):
		self.dic = {}
		self.dic[X86_REG_RAX] = {X86_REG_RAX:None , X86_REG_EAX:None , X86_REG_AX:None , X86_REG_AH:None , X86_REG_AL:None}
		self.dic[X86_REG_RBX] = {X86_REG_RBX:None , X86_REG_EBX:None , X86_REG_BX:None , X86_REG_BH:None , X86_REG_BL:None}
		self.dic[X86_REG_RCX] = {X86_REG_RCX:None , X86_REG_ECX:None , X86_REG_CX:None , X86_REG_CH:None , X86_REG_CL:None}
		self.dic[X86_REG_RDX] = {X86_REG_RDX:None , X86_REG_EDX:None , X86_REG_DX:None , X86_REG_DH:None , X86_REG_DL:None}
		self.dic[X86_REG_RSI] = {X86_REG_RSI:None , X86_REG_ESI:None , X86_REG_SI:None , X86_REG_SIL:None}
		self.dic[X86_REG_RDI] = {X86_REG_RDI:None , X86_REG_EDI:None , X86_REG_DI:None , X86_REG_DIL:None}
		self.dic[X86_REG_RBP] = {X86_REG_RBP:None , X86_REG_EBP:None , X86_REG_BP:None , X86_REG_BPL:None}
		self.dic[X86_REG_RSP] = {X86_REG_RSP:None , X86_REG_ESP:None , X86_REG_SP:None , X86_REG_SPL:None}
		self.dic[X86_REG_R8]  = {X86_REG_R8:None , X86_REG_R8D:None , X86_REG_R8W:None , X86_REG_R8B:None}
		self.dic[X86_REG_R9]  = {X86_REG_R9:None , X86_REG_R9D:None , X86_REG_R9W:None , X86_REG_R9B:None}
		self.dic[X86_REG_R10] = {X86_REG_R10:None , X86_REG_R10D:None , X86_REG_R10W:None , X86_REG_R10B:None}
		self.dic[X86_REG_R11] = {X86_REG_R11:None , X86_REG_R11D:None , X86_REG_R11W:None , X86_REG_R11B:None}
		self.dic[X86_REG_R12] = {X86_REG_R12:None , X86_REG_R12D:None , X86_REG_R12W:None , X86_REG_R12B:None}
		self.dic[X86_REG_R13] = {X86_REG_R13:None , X86_REG_R13D:None , X86_REG_R13W:None , X86_REG_R13B:None}
		self.dic[X86_REG_R14] = {X86_REG_R14:None , X86_REG_R14D:None , X86_REG_R14W:None , X86_REG_R14B:None}
		self.dic[X86_REG_R15] = {X86_REG_R15:None , X86_REG_R15D:None , X86_REG_R15W:None , X86_REG_R15B:None}
		for value in self.dic.values():
			for key in value.keys():
				self.dic[key] = value

	def __getitem__(self,key):
		return self.dic[key][key]

	def __setitem__(self,key,value):
		for reg in regSizeTable[key]:
			self.dic[reg][reg] = None
		self.dic[key][key] = value

	def gets(self,key):
		return self.dic[key].items()

regSizeTable = {}
regSizeTable[X86_REG_RAX] = [X86_REG_RAX , X86_REG_EAX  , X86_REG_AX   , X86_REG_AH   , X86_REG_AL]
regSizeTable[X86_REG_EAX] = [X86_REG_EAX , X86_REG_AX   , X86_REG_AH   , X86_REG_AL]
regSizeTable[X86_REG_AX]  = [X86_REG_AX  , X86_REG_AH   , X86_REG_AL]
regSizeTable[X86_REG_AH]  = [X86_REG_AL]
regSizeTable[X86_REG_AL]  = [X86_REG_AL]

regSizeTable[X86_REG_RBX] = [X86_REG_RBX , X86_REG_EBX  , X86_REG_BX   , X86_REG_BH   , X86_REG_BL]
regSizeTable[X86_REG_EBX] = [X86_REG_EBX , X86_REG_BX   , X86_REG_BH   , X86_REG_BL]
regSizeTable[X86_REG_BX]  = [X86_REG_BX  , X86_REG_BH   , X86_REG_BL]
regSizeTable[X86_REG_BH]  = [X86_REG_BL]
regSizeTable[X86_REG_BL]  = [X86_REG_BL]

regSizeTable[X86_REG_RCX] = [X86_REG_RCX , X86_REG_ECX  , X86_REG_CX   , X86_REG_CH   , X86_REG_CL]
regSizeTable[X86_REG_ECX] = [X86_REG_ECX , X86_REG_CX   , X86_REG_CH   , X86_REG_CL]
regSizeTable[X86_REG_CX]  = [X86_REG_CX  , X86_REG_CH   , X86_REG_CL]
regSizeTable[X86_REG_CH]  = [X86_REG_CL]
regSizeTable[X86_REG_CL]  = [X86_REG_CL]

regSizeTable[X86_REG_RDX] = [X86_REG_RDX , X86_REG_EDX  , X86_REG_DX   , X86_REG_DH   , X86_REG_DL]
regSizeTable[X86_REG_EDX] = [X86_REG_EDX , X86_REG_DX   , X86_REG_DH   , X86_REG_DL]
regSizeTable[X86_REG_DX]  = [X86_REG_DX  , X86_REG_DH   , X86_REG_DL]
regSizeTable[X86_REG_DH]  = [X86_REG_DL]
regSizeTable[X86_REG_DL]  = [X86_REG_DL]

regSizeTable[X86_REG_RSI] = [X86_REG_RSI , X86_REG_ESI  , X86_REG_SI   , X86_REG_SIL ]
regSizeTable[X86_REG_ESI] = [X86_REG_ESI , X86_REG_SI   , X86_REG_SIL ]
regSizeTable[X86_REG_SI]  = [X86_REG_SI  , X86_REG_SIL ]
regSizeTable[X86_REG_SIL] = [X86_REG_SIL ]

regSizeTable[X86_REG_RDI] = [X86_REG_RDI , X86_REG_EDI  , X86_REG_DI   , X86_REG_DIL ]
regSizeTable[X86_REG_EDI] = [X86_REG_EDI , X86_REG_DI   , X86_REG_DIL ]
regSizeTable[X86_REG_DI]  = [X86_REG_DI  , X86_REG_DIL ]
regSizeTable[X86_REG_DIL] = [X86_REG_DIL ]

regSizeTable[X86_REG_RBP] = [X86_REG_RBP , X86_REG_EBP  , X86_REG_BP   , X86_REG_BPL ]
regSizeTable[X86_REG_EBP] = [X86_REG_EBP , X86_REG_BP   , X86_REG_BPL ]
regSizeTable[X86_REG_BP]  = [X86_REG_BP  , X86_REG_BPL ]
regSizeTable[X86_REG_BPL] = [X86_REG_BPL ]

regSizeTable[X86_REG_RSP] = [X86_REG_RSP , X86_REG_ESP  , X86_REG_SP   , X86_REG_SPL ]
regSizeTable[X86_REG_ESP] = [X86_REG_ESP , X86_REG_SP   , X86_REG_SPL ]
regSizeTable[X86_REG_SP]  = [X86_REG_SP  , X86_REG_SPL ]
regSizeTable[X86_REG_SPL] = [X86_REG_SPL ]

regSizeTable[X86_REG_R8]   = [X86_REG_R8  , X86_REG_R8D  , X86_REG_R8W  , X86_REG_R8B ]
regSizeTable[X86_REG_R8D]  = [X86_REG_R8D , X86_REG_R8W  , X86_REG_R8B ]
regSizeTable[X86_REG_R8W]  = [X86_REG_R8W , X86_REG_R8B ]
regSizeTable[X86_REG_R8B]  = [X86_REG_R8B ]

regSizeTable[X86_REG_R9]   = [X86_REG_R9  , X86_REG_R9D  , X86_REG_R9W  , X86_REG_R9B ]
regSizeTable[X86_REG_R9D]  = [X86_REG_R9D , X86_REG_R9W  , X86_REG_R9B ]
regSizeTable[X86_REG_R9W]  = [X86_REG_R9W , X86_REG_R9B ]
regSizeTable[X86_REG_R9B]  = [X86_REG_R9B ]

regSizeTable[X86_REG_R10]   = [X86_REG_R10  , X86_REG_R10D  , X86_REG_R10W  , X86_REG_R10B ]
regSizeTable[X86_REG_R10D]  = [X86_REG_R10D , X86_REG_R10W  , X86_REG_R10B ]
regSizeTable[X86_REG_R10W]  = [X86_REG_R10W , X86_REG_R10B ]
regSizeTable[X86_REG_R10B]  = [X86_REG_R10B ]

regSizeTable[X86_REG_R11]   = [X86_REG_R11  , X86_REG_R11D  , X86_REG_R11W  , X86_REG_R11B ]
regSizeTable[X86_REG_R11D]  = [X86_REG_R11D , X86_REG_R11W  , X86_REG_R11B ]
regSizeTable[X86_REG_R11W]  = [X86_REG_R11W , X86_REG_R11B ]
regSizeTable[X86_REG_R11B]  = [X86_REG_R11B ]

regSizeTable[X86_REG_R12]   = [X86_REG_R12  , X86_REG_R12D  , X86_REG_R12W  , X86_REG_R12B ]
regSizeTable[X86_REG_R12D]  = [X86_REG_R12D , X86_REG_R12W  , X86_REG_R12B ]
regSizeTable[X86_REG_R12W]  = [X86_REG_R12W , X86_REG_R12B ]
regSizeTable[X86_REG_R12B]  = [X86_REG_R12B ]

regSizeTable[X86_REG_R13]   = [X86_REG_R13  , X86_REG_R13D  , X86_REG_R13W  , X86_REG_R13B ]
regSizeTable[X86_REG_R13D]  = [X86_REG_R13D , X86_REG_R13W  , X86_REG_R13B ]
regSizeTable[X86_REG_R13W]  = [X86_REG_R13W , X86_REG_R13B ]
regSizeTable[X86_REG_R13B]  = [X86_REG_R13B ]

regSizeTable[X86_REG_R14]   = [X86_REG_R14  , X86_REG_R14D  , X86_REG_R14W  , X86_REG_R14B ]
regSizeTable[X86_REG_R14D]  = [X86_REG_R14D , X86_REG_R14W  , X86_REG_R14B ]
regSizeTable[X86_REG_R14W]  = [X86_REG_R14W , X86_REG_R14B ]
regSizeTable[X86_REG_R14B]  = [X86_REG_R14B ]

if __name__ == '__main__':
	from pprint import pprint
	reg4ir = REG4IR()
	reg4ir[X86_REG_AL] = 12
	reg4ir[X86_REG_EAX] = 1234
	pprint(reg4ir.dic[X86_REG_RAX])