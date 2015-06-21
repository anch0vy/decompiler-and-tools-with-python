from type import REG
from elfparser import ELF
from disasm import md32,md64

elf = ELF(open('a.out','rb'))
for i in md32.disasm('ff35d8960408ff25dc96040800000000ff25e09604086800000000e9e0ffffffff25e49604086808000000e9d0ffffffff25e89604086810000000e9c0ffffffff25ec9604086818000000e9b0ffffff'.decode('hex'),4195424):
	print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
