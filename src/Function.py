

class FunctionCFG:
	def __init__(self,function):
	#	self.function = function
		self.startAddr= function.addr
		self.graph    = function.graph.copy()
		self.blockDisassembly = {}
		self.parseAllBlocks(function)

	def parseAllBlocks(self,function):
		for block in function.blocks:
			capBlock = block.capstone
			sentences = list()
			for insn in capBlock.insns:
				ins = insn.insn
				sentences.append(Sentence(ins.addr,ins.mnemonic,ins.op_str))
			sentences = filter(lambda sentence:sentence.pattern!=None, sentences)
			self.blockDisassembly[block.addr]=sentences		






class Sentence:
	action ={
	"AAA":markForDelete,
	"AAD":markForDelete,
	"AAM":markForDelete,
	"AAS":markForDelete,
	"ADC":patternASSIGN,
	"ADD":patternASSIGN_OR_ASSIGNC,
	"ADDPD":patternASSIGN_OR_ASSIGNC,
	"ADDPS":patternASSIGN_OR_ASSIGNC,
	"ADDSD":patternASSIGN_OR_ASSIGNC,
	"ADDSS":patternASSIGN_OR_ASSIGNC,
	"ADDSUBPD":patternASSIGN_OR_ASSIGNC,
	"ADDSUBPS":patternASSIGN_OR_ASSIGNC,
	"AESDEC":markForDelete, 
	"AESDECLAST":markForDelete, 
	"AESENC":markForDelete,
	"AESENCLAST":markForDelete, 
	"AESIMC":markForDelete, 
	"AESKEYGENASSIST":markForDelete,
	"ANDNPD":patternASSIGN_OR_ASSIGNC,
	"ANDNPS":patternASSIGN_OR_ASSIGNC,
	"AND":patternASSIGN_OR_ASSIGNC,
	"ANDPD":patternASSIGN_OR_ASSIGNC,
	"ANDPS":patternASSIGN_OR_ASSIGNC,
	"ARPL":markForDelete,
	

	}

	def __init__(self,addr,mnemonic,operands):
		self.addr = addr
		self.op = mnemonic
		self.operands = operands.split(',')
		self.convertToMAIL()

	def convertToMAIL(self):


	def markForDelete(self):
		self.pattern = ""

	def patternASSIGN(self):
		self.pattern = "ASSIGN"

	def patternASSIGNC(self):
		self.pattern = "ASSIGNC"

	def patternASSIGN_OR_ASSIGNC(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "ASSIGN"
		else:
			self.pattern = "ASSIGNC"




	def __repr__(self):
		return "%3s  :%15s %-10s" %(self.addr,self.op,self.operands)