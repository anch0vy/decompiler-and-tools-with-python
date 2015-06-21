from numpy import float32,float64
from struct import pack,unpack
class REG:
	def __init__(self,regname):
		self.v = 0
		self.name = regname

	def get(self,bit):
		return int(pack('>Q',self.v).encode('hex')[(64 - bit)/4:],16)

	def set(self,op,bit):
		self.v = self.v >> bit << bit
		self.v += op

	def add(self,op,bit = 64):
		v = get(self.v,bit)
		v += op
		self.set(v,bit)

	def sub(self,op,bit = 64):
		v = get(self.v,bit)
		v -= op
		self.set(v,bit)

	# def mul(self,op,bit = 64):
	# 	v = get(self.v,bit)
	# 	v *= op
	# 	self.set(v,bit)

	# def imul(self,op,bit = 64):
	# 	v = get(self.v,bit)
	# 	self.set(v,bit)

	def xor(self,op,bit = 64):
		v = get(self.v,bit)
		v ^= op
		self.set(v,bit)

	def and_(self,op,bit = 64):
		v = get(self.v,bit)
		v &= op
		self.set(v,bit)

	def or_(self,op,bit = 64):
		v = get(self.v,bit)
		v |= op
		self.set(v,bit)

	def mov(self,op,bit = 64):
		v = get(self.v,bit)
		v = op
		self.set(v,bit)

class ST:
	def __init(self):
		self.v = 0