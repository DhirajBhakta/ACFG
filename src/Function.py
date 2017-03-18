import networkx as nx


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
				sentences.append(Sentence(ins.address,ins.mnemonic,ins.op_str))
			sentences = filter(lambda sentence:sentence.pattern!=None, sentences)
			self.blockDisassembly[block.addr]=sentences



#-------------------------------------------------------------------------------------
#funcS	:FunctionCFG instance of a Test 'S'ample
#funcM	:FunctionCFG instance of a 'M'alware 
#functionComparator checks if a Sample FunctionCFG matches(subgraph isomorphically) a Malware FunctionCFG
def functionComparator(funcS,funcM):
	graph_matcher = nx.isomorphism.DiGraphMatcher(funcS.graph,funcM.graph)
	if(graph_matcher.subgraph_is_isomorphic()):
		for blockS,blockM in graph_matcher.mapping.items():
			for sentenceS,sentenceM in zip(funcS.blockDisassembly[blockS.addr],funcM.blockDisassembly[blockM.addr]):
				if sentenceS.pattern != sentenceM.pattern:
					return False
		return True

	else:
		return False
#-------------------------------------------------------------------------------------






class Sentence:
	action ={
	"AAA":markForDelete,
	"AAD":markForDelete,
	"AAM":markForDelete,
	"AAS":markForDelete,
	"ADC":patternASSIGN,
	"ADD":patternASSIGN_OR_ASSIGNC_all,
	"ADDPD":patternASSIGN_OR_ASSIGNC_all,
	"ADDPS":patternASSIGN_OR_ASSIGNC_all,
	"ADDSD":patternASSIGN_OR_ASSIGNC_all,
	"ADDSS":patternASSIGN_OR_ASSIGNC_all,
	"ADDSUBPD":patternASSIGN_OR_ASSIGNC_all,
	"ADDSUBPS":patternASSIGN_OR_ASSIGNC_all,
	"AESDEC":markForDelete, 
	"AESDECLAST":markForDelete, 
	"AESENC":markForDelete,
	"AESENCLAST":markForDelete, 
	"AESIMC":markForDelete, 
	"AESKEYGENASSIST":markForDelete,
	"ANDNPD":patternASSIGN_OR_ASSIGNC_all,
	"ANDNPS":patternASSIGN_OR_ASSIGNC_all,
	"AND":patternASSIGN_OR_ASSIGNC_all,
	"ANDPD":patternASSIGN_OR_ASSIGNC_all,
	"ANDPS":patternASSIGN_OR_ASSIGNC_all,
	"ARPL":markForDelete,
	"BLENDPD":patternASSIGN_OR_ASSIGNC_1,
	"BLENDPS":patternASSIGN_OR_ASSIGNC_1, 
	"BLENDVPD":patternASSIGN_OR_ASSIGNC_1,
	"BLENDVPS":patternASSIGN_OR_ASSIGNC_1,
	"BOUND":markForDelete,
	"BSF":patternLIBCALL_OR_LIBCALLC_all,
	"BSR":patternLIBCALL_OR_LIBCALLC_all,
	"BSWAP":patternLIBCALL_OR_LIBCALLC_all,
	"BTC":patternLIBCALL_OR_LIBCALLC_all,
	"BTR":patternLIBCALL_OR_LIBCALLC_all,
	"BTS":patternLIBCALL_OR_LIBCALLC_all,
	"CALL":patternCALL_OR_CALLC,			#REVIEW "CALL"
	"CBW":patternASSIGN,
	"CDQ":patternASSIGN,
	"CDQE":patternASSIGN,
	"CLFLUSH":markForDelete,
	"CLTS":markForDelete,
	"CLC":patternFLAG,
	"CLD":patternFLAG,
	"CLI":patternFLAG,
	"CLGI":patternFLAG,
	"CMC":markForDelete,
	"CMOVCC":patternCONTROL_OR_CONTROLC_all, #REVIEW "CMOVcc" ...whether Case matters??
	"CMP":patternLIBCALL_OR_LIBCALLC_all,
	"CMPEQPD":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPEQPS":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPEQSD":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPEQSS":patternLIBCALL_OR_LIBCALLC_all,
	"CMPLT":patternLIBCALL_OR_LIBCALLC_all,
	"CMPLE":patternLIBCALL_OR_LIBCALLC_all,
	"CMPNEQ":patternLIBCALL_OR_LIBCALLC_all,
	"CMPNLT":patternLIBCALL_OR_LIBCALLC_all,
	"CMPNLE":patternLIBCALL_OR_LIBCALLC_all,
	"CMPORD":patternLIBCALL_OR_LIBCALLC_all,
	"CMPUORD":patternLIBCALL_OR_LIBCALLC_all,
	"CMPS":patternLIBCALL_OR_LIBCALLC_all,
	"CMPSB":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPSW":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPSD":patternLIBCALL_OR_LIBCALLC_all, 
	"CMPSQ":patternLIBCALL_OR_LIBCALLC_all,
	"CMPXCHG":patternLIBCALL_OR_LIBCALLC_all,
	"CMPXCHG8GB":patternLIBCALL_OR_LIBCALLC_all,
	"CMPXCHG16GB":patternLIBCALL_OR_LIBCALLC_all,
	"COMISD":patternLIBCALL_OR_LIBCALLC_all,
	"COMISS":patternLIBCALL_OR_LIBCALLC_all,
	"CPUID":markForDelete,
	"CRC32":markForDelete,
	"CQO":patternASSIGN,
	"CVTDQ2PD":patternASSIGN_OR_ASSIGNC_0, 
	"CVTDQ2PS":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPD2DQ":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPD2PI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPD2PS":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPH2PS":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPI2PD":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPI2PS":patternASSIGN_OR_ASSIGNC_0,
	"CVTPS2DQ":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPS2PD":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPS2PH":patternASSIGN_OR_ASSIGNC_0, 
	"CVTPS2PI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTSD2SI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTSD2SS":patternASSIGN_OR_ASSIGNC_0, 
	"CVTSI2SD":patternASSIGN_OR_ASSIGNC_0, 
	"CVTSI2SS":patternASSIGN_OR_ASSIGNC_0,
	"CVTSS2SD":patternASSIGN_OR_ASSIGNC_0, 
	"CVTSS2SI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTPD2DQ":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTPD2PI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTPS2DQ":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTPS2PI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTSD2SI":patternASSIGN_OR_ASSIGNC_0, 
	"CVTTSS2SI":patternASSIGN_OR_ASSIGNC_0,
	"CWD":patternASSIGN,
	"CWDE":patternASSIGN,
	"DAA":markForDelete,
	"DAS":markForDelete,
	"DEC":patternASSIGN,
	"DIV":patternASSIGN_OR_ASSIGNC_1,
	"DIVPD":patternASSIGN_OR_ASSIGNC_1, 
	"DIVPS":patternASSIGN_OR_ASSIGNC_1, 
	"DIVSD":patternASSIGN_OR_ASSIGNC_1,
	"DIVSS":patternASSIGN_OR_ASSIGNC_1,
	"DDPD":patternASSIGN_OR_ASSIGNC_all,
	"DDPS":patternASSIGN_OR_ASSIGNC_all,
	"EMMS":markForDelete,
	"ENTER":markForDelete,
	"EXTRACTPS":patternASSIGN_OR_ASSIGNC_1,
	"F2XMI":patternLIBCALL,
	"FABS":patternLIBCALL,
	"FADD":patternASSIGN,
	"FADDP":patternASSIGN,
	"FBLD":patternASSIGN_OR_ASSIGNC_0,
	"FBSTP":patternASSIGN,
	"FCHS":patternASSIGN,
	"FCLEX":markForDelete,
	"FCMOVB":patternCONTROL, 
	"FCMOVBE":patternCONTROL, 
	"FCMOVE":patternCONTROL, 
	"FCMOVNB":patternCONTROL, 
	"FCMOVNBE":patternCONTROL, 
	"FCMOVNE":patternCONTROL,
	"FCMOVNU":patternCONTROL, 
	"FCMOVU":patternCONTROL,
	"FCOM":patternLIBCALL, 
	"FCOMI":patternLIBCALL, 
	"FCOMIP":patternLIBCALL, 
	"FCOMP":patternLIBCALL, 
	"FCOMPP":patternLIBCALL,
	"FCOS":patternLIBCALL,
	"FDECSTP":markForDelete,
	"FDIVR":patternASSIGN,
	"FDIVRP":patternASSIGN,
	"FDIV":patternASSIGN,
	"FDIVP":patternASSIGN,
	"FEDISI":markForDelete, 
	"FEMMS":markForDelete, 
	"FENI":markForDelete,
	"FFREE":markForDelete,
	"FIADD":patternASSIGN,
	"FICOM":patternLIBCALL_OR_LIBCALLC_0,
	"FICOMP":patternASSIGN,
	"FIDIVR":patternASSIGN,
	"FIDIV":patternASSIGN,
	"FILD":patternASSIGN_OR_ASSIGNC_0,
	"FIMUL":patternASSIGN,
	"FINCSTP":markForDelete,
	"FINIT":markForDelete,
	"FIST":patternASSIGN,
	"FISTP":patternASSIGN,
	"FISTTP":patternASSIGN,
	"FISUBR":patternASSIGN,
	"FISUB":patternASSIGN,
	"FLDCW":markForDelete,
	"FLDENV":markForDelete,
	"FLD":patternASSIGNC,
	"FLD1":patternASSIGNC, 
	"FLDL2E":patternASSIGNC, 
	"FLDL2T":patternASSIGNC, 
	"FLDLG2":patternASSIGNC, 
	"FLDLN2":patternASSIGNC, 
	"FLDPI":patternASSIGNC, 
	"FLDZ":patternASSIGNC,
	"FMUL":patternASSIGN,
	"FMULP":patternASSIGN,
	"FNCLEX":markForDelete,
	"FNINIT":markForDelete,
	"FNSAVE":markForDelete,
	"FNSTCW":markForDelete,
	"FNSTENV":markForDelete,
	"FNSTSW":markForDelete,
	"FPATAN":patternLIBCALL,
	"FPREM":patternASSIGN,
	"FPREM1":patternASSIGN,
	"FPTAN":patternLIBCALL,
	"FRNDINT":patternLIBCALL,
	"FRSTOR":markForDelete,
	"FSAVE":markForDelete,
	"FSCALE":patternLIBCALL,
	"FSETPM":markForDelete,
	"FSIN":patternLIBCALL,
	"FSINCOS":patternLIBCALL,
	"FSQRT":patternLIBCALL,
	"FST":patternASSIGN,
	"FSTP":patternASSIGN,
	"FSTCW":markForDelete,
	"FSTENV":markForDelete,
	"FSTSW":markForDelete
	"FSUBR":patternASSIGN,
	"FSUBRP":patternASSIGN,
	"FSUB":patternASSIGN,
	"FSUBP":patternASSIGN,
	"FTST":patternLIBCALLC,
	"FUCOM":patternLIBCALL,
	"FUCOMI":patternLIBCALL, 
	"FUCOMIP":patternLIBCALL, 
	"FUCOMP":patternLIBCALL, 
	"FUCOMPP":patternLIBCALL,
	"FXAM":patternLIBCALLC,
	"FXCH":patternLIBCALL,
	"FXRSTOR":markForDelete,
	"FXRSTOR64":markForDelete,
	"FXSAVE":markForDelete,
	"FXSAVE64"markForDelete,
	"FXTRACT":markForDelete,
	"FYL2XP1":patternASSIGN,
	"FYL2X":patternASSIGN,
	"GETSEC":markForDelete,
	"HADDPD":patternASSIGN_OR_ASSIGNC_all,
	"HADDPS":patternASSIGN_OR_ASSIGNC_all,
	"HLT":patternHALT,
	"HSUBPD":patternASSIGN_OR_ASSIGNC_all,
	"HSUBPS":patternASSIGN_OR_ASSIGNC_all,
	"IDIV":patternASSIGN_OR_ASSIGNC_1,
	"IMUL":	specialIMUL,
	"IN":patternASSIGN_OR_ASSIGNC_1,
	"INC":patternASSIGN,
	"INS":patternASSIGN,
	"INSB":patternASSIGN,
	"INSW":patternASSIGN,
	"INSD":patternASSIGN,
	"INSERTPS":patternASSIGN_OR_ASSIGNC_1,
	"INT":markForDelete,
	"INT 3":markForDelete,
	"INVD":markForDelete, 
	"INVEPT":markForDelete, 
	"INVLPG":markForDelete, 
	"INVLPGA":markForDelete, 
	"INVPCID":markForDelete, 
	"INVVPID":markForDelete,
	"IRET":patternJUMPSTACK,
	"JMP":specialJMP,
	"JAE":specialJxxx,
	"JA":specialJxxx,
	"JBE":specialJxxx,
	"JB":specialJxxx,
	"JCXZ":specialJxxx,
	"JC":specialJxxx,
	"JECXZ":specialJxxx,
	"JRCXZ":specialJxxx,
	"JE":specialJxxx,
	"JGE":specialJxxx,
	"JG":specialJxxx,
	"JLE":specialJxxx,
	"JL":specialJxxx,
	"JNAE":specialJxxx,
	"JNA":specialJxxx,
	"JNBE":specialJxxx,
	"JNB":specialJxxx,
	"JNC":specialJxxx,
	"JNE":specialJxxx,
	"JNGE":specialJxxx,
	"JNG":specialJxxx,
	"JNLE":specialJxxx,
	"JNL":specialJxxx,
	"JNO":specialJxxx,
	"JNP":specialJxxx,
	"JNS":specialJxxx,
	"JNZ":specialJxxx,
	"JO":specialJxxx,
	"JP":specialJxxx,
	"JPE":specialJxxx,
	"JPO":specialJxxx,
	"JS":specialJxxx,
	"JZ":specialJxxx,
	"LAHF":patternFLAG,
	"LAR":patternASSIGN,
	"LDDQU":patternASSIGN,
	"LDMXCSR":patternASSIGN_OR_ASSIGNC_0,
	"LDS":patternASSIGN_OR_ASSIGNC_1,
	"LEAVE":markForDelete,
	"LEA":patternASSIGN_OR_ASSIGNC_1,
	"LES":patternASSIGN_OR_ASSIGNC_1,
	"LFS":patternASSIGN_OR_ASSIGNC_1,
	"LFENCE":markForDelete,
	"LGS":patternASSIGN_OR_ASSIGNC_1,
	"LGDT":patternASSIGN_OR_ASSIGNC_0,
	"LIDT":patternASSIGN_OR_ASSIGNC_0,
	"LLDT":patternASSIGN_OR_ASSIGNC_0,
	"LMSW":patternASSIGN_OR_ASSIGNC_0,
	"LOCK":patternLOCK,
	"LODS":patternASSIGN,
	"LOOP":patternJUMP_OR_JUMPC_0,
	"LSL":patternASSIGN_OR_ASSIGNC_1,
	"LSS":patternASSIGN_OR_ASSIGNC_1,
	"LTR":patternASSIGN_OR_ASSIGNC_0,
	"LZCNT":markForDelete,
	"MASKMOVDQU":patternASSIGN_OR_ASSIGNC_0,
	"MASKMOVQ":patternASSIGN_OR_ASSIGNC_0,
	"MAX":patternLIBCALL_OR_LIBCALLC_all,
	"MIN":patternLIBCALL_OR_LIBCALLC_all, # doubt: about number of args. and variations (MAXSS,MAXPD,MINSS...etc)
	"MFENCE":markForDelete,
	"MONITOR":markForDelete,
	"MOVSD":patternASSIGN,
	"MOVSB":patternASSIGN,
	"MOVSW":patternASSIGN,
	"MOVSQ":patternASSIGN,
	"MOVSLDUP":patternASSIGN_OR_ASSIGNC_1,
	"MOVSHDUP":patternASSIGN_OR_ASSIGNC_1,
	"MOVSS":patternASSIGN_OR_ASSIGNC_1,
	"MOVSX":patternASSIGN_OR_ASSIGNC_1,
	"MOVSXD":patternASSIGN_OR_ASSIGNC_1,
	"MOVS":patternASSIGN,
	"MOV":patternASSIGN_OR_ASSIGNC_1,
	"MPSADBW":markForDelete,
	"MULPD":patternASSIGN_OR_ASSIGNC_all,
	"MULPS":patternASSIGN_OR_ASSIGNC_all,
	"MULSD":patternASSIGN_OR_ASSIGNC_all,
	"MULSS":patternASSIGN_OR_ASSIGNC_all,
	"MUL":patternASSIGN_OR_ASSIGNC_1,
	"MWAIT":markForDelete,
	"NEG":patternASSIGN_OR_ASSIGNC_0,
	"NOT":patternASSIGN_OR_ASSIGNC_0,
	"OR":patternASSIGN_OR_ASSIGNC_all,
	"ORPD":patternASSIGN_OR_ASSIGNC_all,
	"ORPS":patternASSIGN_OR_ASSIGNC_all,
	"OUTS":patternASSIGN,
	"OUT":patternASSIGN,
	"PABSB":patternLIBCALL_OR_LIBCALLC_1,
	"PACK":patternASSIGN,
	"PADD":patternASSIGN_OR_ASSIGNC_all,
	"PALIGNR":patternASSIGN,
	"PANDN":patternASSIGN_OR_ASSIGNC_all,
	"PAND":patternASSIGN_OR_ASSIGNC_all,
	"PAUSE":markForDelete,
	"PAVG":patternLIBCALL_OR_LIBCALLC_all,
	"PBLEND":patternASSIGN,
	"PCLMUL":patternASSIGN_OR_ASSIGNC_all,
	"PCMPEQB":patternCONTROL_OR_CONTROLC_all,
	"PCMPEQW":patternCONTROL_OR_CONTROLC_all,	
	"PCMPEQD":patternCONTROL_OR_CONTROLC_all,
	"PCMPEQQ":patternCONTROL_OR_CONTROLC_all,
	"PCMPGTB":patternCONTROL_OR_CONTROLC_all,
	"PCMPGTW":patternCONTROL_OR_CONTROLC_all,	
	"PCMPGTD":patternCONTROL_OR_CONTROLC_all,
	"PCMPGTQ":patternCONTROL_OR_CONTROLC_all,
	"PCMPESTRI":patternLIBCALL_OR_LIBCALLC_all,
	"PCMPISTRI":patternLIBCALL_OR_LIBCALLC_all,  
	"PCMPESTRM":patternLIBCALL_OR_LIBCALLC_all, 
	"PCMPISTRM":patternLIBCALL_OR_LIBCALLC_all,
	"PEXTRB":patternLIBCALL_OR_LIBCALLC_12,	
	"PEXTRW":patternLIBCALL_OR_LIBCALLC_12,
	"PEXTRD":patternLIBCALL_OR_LIBCALLC_12,
	"PEXTRQ":patternLIBCALL_OR_LIBCALLC_12,
	"PF2ID":patternASSIGN_OR_ASSIGNC_1,
	"PF2IW":patternASSIGN_OR_ASSIGNC_1,
	"PFACC":patternASSIGN,
	"PFNACC":patternASSIGN,
	"PFPNACC":patternASSIGN,	
	"PFADD":patternASSIGN_OR_ASSIGNC_all,
	"PFCMPEQ":patternCONTROL_OR_CONTROLC_all, 
	"PFCMPGE":patternCONTROL_OR_CONTROLC_all, 
	"PFCMPGT":patternCONTROL_OR_CONTROLC_all,
	"PFMAX":patternASSIGN_OR_ASSIGNC_all,
	"PFMIN":patternASSIGN_OR_ASSIGNC_all,
	"PFMUL":patternASSIGN_OR_ASSIGNC_all,
	"PFRCP":patternASSIGN_OR_ASSIGNC_1,
	"PFRCPIT1":patternASSIGN_OR_ASSIGNC_1,
	"PFRCPIT2":patternASSIGN_OR_ASSIGNC_1,
	"PFRSQRT":patternLIBCALL_OR_LIBCALLC_1,
	"PFRSQRT1":patternLIBCALL_OR_LIBCALLC_1,
	"PFSUBR":patternASSIGN_OR_ASSIGNC_all,
	"PFSUB":patternASSIGN_OR_ASSIGNC_all,
	"PHADD":patternASSIGN_OR_ASSIGNC_all,
	"PHSUB":patternASSIGN_OR_ASSIGNC_all,
	"PHMIN":patternASSIGN_OR_ASSIGNC_1,
	"PI2FD":patternASSIGN_OR_ASSIGNC_1,
	"PI2FW":patternASSIGN_OR_ASSIGNC_1,
	"PINSRB":patternLIBCALL_OR_LIBCALLC_12,
	"PINSRW":patternLIBCALL_OR_LIBCALLC_12,
	"PMUL":patternASSIGN_OR_ASSIGNC_all,
	"PMADD":patternASSIGN_OR_ASSIGNC_all,
	"PMAX":patternLIBCALL_OR_LIBCALLC_all,
	"PMIN":patternLIBCALL_OR_LIBCALLC_all,
	"PMOV":patternASSIGN_OR_ASSIGNC_1,
	"POPA":patternSTACK,
	"POPAD":patternSTACK,
	"POPCNT":patternLIBCALL_OR_LIBCALLC_1,
	"POPS":patternFLAGSTACK,
	"POP":patternSTACK,
	"POR":patternASSIGN_OR_ASSIGNC_all,
	"PREFETCH":markForDelete,
	"PSAD":markForDelete,
	"PSHUF":markForDelete,
	"PSIGN":markForDelete,
	"PSL":patternASSIGN_OR_ASSIGNC_all,
	"PSR":patternASSIGN_OR_ASSIGNC_all,
	"PSUB":patternASSIGN_OR_ASSIGNC_all,
	"PSWAP":patternLIBCALL_OR_LIBCALLC_all,
	"PTEST":patternTEST_OR_TESTC_all,
	"PUSHA":patternSTACK,
	"PUSHF":patternFLAGSTACK,
	"PUSH":patternSTACK_OR_STACKC_0,
	"PUNPCKHBW":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKHWD":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKHDQ":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKHQDQ"patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKLBW":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKLWD":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKLDQ":patternLIBCALL_OR_LIBCALLC_all,
	"PUNPCKLQDQ":patternLIBCALL_OR_LIBCALLC_all,
	"PXOR":patternASSIGN_OR_ASSIGNC_all,
	"RCPPS":patternASSIGN_OR_ASSIGNC_1,
	"PCPSS":patternASSIGN_OR_ASSIGNC_1,
	"RCL":markForDelete,
	"RCR":markForDelete,
	"RDMSR":patternASSIGN,
	"RDPMC":patternASSIGN,
	"RDRAND":markForDelete,
	"RDTSC":markForDelete,
	"RDTSCP":markForDelete,
	"RDFSBASE":patternASSIGN,
	"RDGSBASE":patternASSIGN,
	"RET":patternJUMPSTACK,
	"RETF":patternJUMPSTACK,
	"ROL":markForDelete,
	"ROR":markForDelete,
	"ROUNDPD":patternLIBCALL_OR_LIBCALLC_1,
	"ROUNDPS":patternLIBCALL_OR_LIBCALLC_1,
	"ROUNDSD":patternLIBCALL_OR_LIBCALLC_1,
	"ROUNDSS":patternLIBCALL_OR_LIBCALLC_1,
	"RSM":markForDelete,
	"RSQRTPS":patternLIBCALL_OR_LIBCALLC_1,
	"RSQRTSS":patternLIBCALL_OR_LIBCALLC_1,
	"SAHF":patternFLAG,
	"SALC":patternCONTROLC,
	"SAL":patternASSIGN_OR_ASSIGNC_all,
	"SAR":patternASSIGN_OR_ASSIGNC_all,
	"SBB":patternASSIGN_OR_ASSIGNC_all,
	"SCAS":patternLIBCALL,
	"SETAE":patternCONTROLC,
	"SETA":patternCONTROLC,
	"SETBE":patternCONTROLC,
	"SETB":patternCONTROLC,
	"SETCXZ":patternCONTROLC,
	"SETC":patternCONTROLC,
	"SETECXZ":patternCONTROLC,
	"SETRCXZ":patternCONTROLC,
	"SETE":patternCONTROLC,
	"SETGE":patternCONTROLC,
	"SETG":patternCONTROLC,
	"SETLE":patternCONTROLC,
	"SETL":patternCONTROLC,
	"SETNAE":patternCONTROLC,
	"SETNA":patternCONTROLC,
	"SETNBE":patternCONTROLC,
	"SETNB":patternCONTROLC,
	"SETNC":patternCONTROLC,
	"SETNE":patternCONTROLC,
	"SETNGE":patternCONTROLC,
	"SETNG":patternCONTROLC,
	"SETNLE":patternCONTROLC,
	"SETNL":patternCONTROLC,
	"SETNO":patternCONTROLC,
	"SETNP":patternCONTROLC,
	"SETNS":patternCONTROLC,
	"SETNZ":patternCONTROLC,
	"SETO":patternCONTROLC,
	"SETP":patternCONTROLC,
	"SETPE":patternCONTROLC,
	"SETPO":patternCONTROLC,
	"SETS":patternCONTROLC,
	"SETZ":patternCONTROLC,
	"SFENCE":markForDelete,
	"SGDT":patternASSIGN,
	"SHLD":patternLIBCALL_OR_LIBCALLC_12,
	"SHRD":patternLIBCALL_OR_LIBCALLC_12,
	"SHR":patternASSIGN_OR_ASSIGNC_all,
	"SHL":patternASSIGN_OR_ASSIGNC_all,
	"SHUFPD":markForDelete,
	"SHUFPS":markForDelete,
	"SIDT":patternASSIGN,
	"SKINIT":markForDelete,
	"SLDT":patternASSIGN,
	"SMSW":markForDelete,
	"SQRTPD":patternLIBCALL_OR_LIBCALLC_1, 
	"SQRTPS":patternLIBCALL_OR_LIBCALLC_1, 
	"SQRTSD":patternLIBCALL_OR_LIBCALLC_1, 
	"SQRTSS":patternLIBCALL_OR_LIBCALLC_1,
	"STC":patternFLAG,
	"STD":patternFLAG,
	"STGI":patternFLAG,
	"STI":patternFLAG,
	"STMXCSR":patternASSIGN_OR_ASSIGNC_0,
	"STOS":patternASSIGN,
	"STR":patternASSIGN,
	"SUB":patternASSIGN_OR_ASSIGNC_all,
	"SUBPD":patternASSIGN_OR_ASSIGNC_all,
	"SUBPS":patternASSIGN_OR_ASSIGNC_all,
	"SUBSD":patternASSIGN_OR_ASSIGNC_all,
	"SUBSS":patternASSIGN_OR_ASSIGNC_all,
	"SWAPGS":patternASSIGN,
	"SYSCALL":markForDelete,
	"SYSENTER":markForDelete,
	"SYSEXIT":markForDelete,
	"SYSRET":markForDelete,
	"TEST":patternTEST_OR_TESTC_all,
	"UCOMISD":patternLIBCALL_OR_LIBCALLC_all, 
	"UCOMISS":patternLIBCALL_OR_LIBCALLC_all,
	"UNPCKHPD":patternLIBCALL_OR_LIBCALLC_all, 
	"UNPCKHPS":patternLIBCALL_OR_LIBCALLC_all,
	"UNPCKLPD":patternLIBCALL_OR_LIBCALLC_all, 
	"UNPCKLPS":patternLIBCALL_OR_LIBCALLC_all,
	"VADDSUBPS":patternASSIGN_OR_ASSIGNC_12,
	"VADDSUBPD":patternASSIGN_OR_ASSIGNC_12,
	"VADDPD":patternASSIGN_OR_ASSIGNC_12,
	"VADDPS":patternASSIGN_OR_ASSIGNC_12,
	"VADDSD":patternASSIGN_OR_ASSIGNC_12,
	"VADDSS":patternASSIGN_OR_ASSIGNC_12,
	"VAESDEC":markForDelete,
	"VAESDECLAST":markForDelete,
	"VAESENC":markForDelete,
	"VAESENCLAST":markForDelete,
	"VAESIMC":markForDelete,
	"VAESKEYGENASSIST":markForDelete,
	"VANDNPD":patternASSIGN_OR_ASSIGNC_12,
	"VANDNPS":patternASSIGN_OR_ASSIGNC_12,
	"VANDPD":patternASSIGN_OR_ASSIGNC_12,
	"VANDPS":patternASSIGN_OR_ASSIGNC_12,
	"VBLENDPD":patternASSIGN_OR_ASSIGNC_12,
	"VBLENDPS":patternASSIGN_OR_ASSIGNC_12,
	"VBLENDVPD":patternASSIGN_OR_ASSIGNC_12,
	"VBLENDVPS":patternASSIGN_OR_ASSIGNC_12,
	"VBROADCASTF128":patternASSIGN_OR_ASSIGNC_1,
	"VBROADCASTSD":patternASSIGN_OR_ASSIGNC_1,
	"VBROADCASTSS":patternASSIGN_OR_ASSIGNC_1,
	"VCMPEQPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPEQPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPEQSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPEQSS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLEPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLEPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLESD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLESS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLTPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLTPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLTSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPLTSS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNEQPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNEQPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNEQSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNEQSS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLEPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLEPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLESD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLESS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLTPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLTPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLTSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPNLTSS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPORDPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPORDPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPORDSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPORDSS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPUNORDPD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPUNORDPS":patternASSIGN_OR_ASSIGNC_12,
	"VCMPUNORDSD":patternASSIGN_OR_ASSIGNC_12,
	"VCMPUNORDSS":patternASSIGN_OR_ASSIGNC_12,
	"VCOMISD":patternLIBCALL_OR_LIBCALLC_all,
	"VCOMISS":patternLIBCALL_OR_LIBCALLC_all,
	"VCMPESTRI":patternASSIGN_OR_ASSIGNC_0,
	"VCVTDQ2PD":patternASSIGN_OR_ASSIGNC_0,
	"VCVTDQ2PS":patternASSIGN_OR_ASSIGNC_0,
	"VCVTPD2DQ":patternASSIGN_OR_ASSIGNC_0,
	"VCVTPD2PS":patternASSIGN_OR_ASSIGNC_0,
	"VCVTPS2DQ":patternASSIGN_OR_ASSIGNC_0,
	"VCVTPS2PD":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSD2SI":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSD2SS":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSI2SD":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSI2SS":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSS2SD":patternASSIGN_OR_ASSIGNC_0,
	"VCVTSS2SI":patternASSIGN_OR_ASSIGNC_0,
	"VCVTTPD2DQ":patternASSIGN_OR_ASSIGNC_0,
	"VCVTTPS2DQ":patternASSIGN_OR_ASSIGNC_0,
	"VCVTTSD2SI":patternASSIGN_OR_ASSIGNC_0,
	"VCVTTSS2SI":patternASSIGN_OR_ASSIGNC_0,
	"VDIVPD":patternASSIGN_OR_ASSIGNC_12,
	"VDIVPS":patternASSIGN_OR_ASSIGNC_12,
	"VDIVSD":patternASSIGN_OR_ASSIGNC_12,
	"VDIVSS":patternASSIGN_OR_ASSIGNC_12,
	"VDPPD":patternASSIGN_OR_ASSIGNC_12,
	"VDPPS":patternASSIGN_OR_ASSIGNC_12,
	"VERR":markForDelete,
	"VERW":markForDelete,
	"VEXTRACTF128":patternASSIGN_OR_ASSIGNC_12,
	"VEXTRACTPS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADDSUB231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD132SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD132SS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD213SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD213SS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD231SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMADD231SS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUBADD231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB132SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB132SS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB213SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB213SS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB231SD":patternASSIGN_OR_ASSIGNC_12,
	"VFMSUB231SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD132SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD132SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD213SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD213SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD231SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMADD231SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB132PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB132PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB132SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB132SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB213PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB213PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB213SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB213SS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB231PD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB231PS":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB231SD":patternASSIGN_OR_ASSIGNC_12,
	"VFNMSUB231SS":patternASSIGN_OR_ASSIGNC_12,
	"VHADDPD":patternASSIGN_OR_ASSIGNC_all,
	"VHADDPS":patternASSIGN_OR_ASSIGNC_all,
	"VHSUBPD":patternASSIGN_OR_ASSIGNC_all,
	"VHSUBPS":patternASSIGN_OR_ASSIGNC_all,
	"VINSERTF128":patternASSIGN_OR_ASSIGNC_2,
	"VINSERTPS":patternASSIGN_OR_ASSIGNC_2,
	"VLDDQU":patternASSIGN,
	"VLDMXCSR":patternASSIGN_OR_ASSIGNC_0,
	"VMASKMOVDQU":patternASSIGN_OR_ASSIGNC_0,
	"VMASKMOVPD":patternASSIGN_OR_ASSIGNC_2,
	"VMASKMOVPS":patternASSIGN_OR_ASSIGNC_2,
	"VMAXPD":patternLIBCALL_OR_LIBCALLC_12,
	"VMAXPS":patternLIBCALL_OR_LIBCALLC_12,
	"VMAXSD":patternLIBCALL_OR_LIBCALLC_12,
	"VMAXSS":patternLIBCALL_OR_LIBCALLC_12,
	"VMCALL":markForDelete,
	"VMCLEAR":markForDelete,
	"VMFUNC":markForDelete,
	"VMLAUNCH":markForDelete,
	"VMLOAD":markForDelete,
	"VMMCALL":markForDelete,
	"VMINPD":patternLIBCALL_OR_LIBCALLC_12,
	"VMINPS":patternLIBCALL_OR_LIBCALLC_12,
	"VMINSD":patternLIBCALL_OR_LIBCALLC_12,
	"VMINSS":patternLIBCALL_OR_LIBCALLC_12,
	"VMOVAPD":patternASSIGN_OR_ASSIGNC_1,
	"VMOVAPS":patternASSIGN_OR_ASSIGNC_1,
	"VMOVD":patternASSIGN_OR_ASSIGNC_1,
	"VMOVDDUP":patternASSIGN_OR_ASSIGNC_1,
	"VMOVDQA":patternASSIGN_OR_ASSIGNC_1,
	"VMOVDQU":patternASSIGN_OR_ASSIGNC_1,
	"VMOVMSKPD":patternASSIGN_OR_ASSIGNC_1,
	"VMOVMSKPS":patternASSIGN_OR_ASSIGNC_1,
	"VMOVNTDQ":patternASSIGN_OR_ASSIGNC_1,
	"VMOVNTDQA":patternASSIGN_OR_ASSIGNC_1,
	"VMOVNTPD":patternASSIGN_OR_ASSIGNC_1,
	"VMOVNTPS":patternASSIGN_OR_ASSIGNC_1,
	"VMOVQ":patternASSIGN_OR_ASSIGNC_1,
	"VMOVUPD":patternASSIGN_OR_ASSIGNC_1,
	"VMOVUPS":patternASSIGN_OR_ASSIGNC_1,
	"VMOVHLPS":patternASSIGN_OR_ASSIGNC_2,
	"VMOVHPD":patternASSIGN_OR_ASSIGNC_2,
	"VMOVHPS":patternASSIGN_OR_ASSIGNC_2,
	"VMOVLHPS":patternASSIGN_OR_ASSIGNC_2,
	"VMOVLPD":patternASSIGN_OR_ASSIGNC_2,
	"VMOVLPS":patternASSIGN_OR_ASSIGNC_2,
	"VMOVSHDUP":patternASSIGN_OR_ASSIGNC_2,
	"VMOVSLDUP":patternASSIGN_OR_ASSIGNC_2,
	"VMOVSD":patternASSIGN_OR_ASSIGNC_2,
	"VMOVSS":patternASSIGN_OR_ASSIGNC_2,
	"VMPSADBW":markForDelete,
	"VMPTRLD":markForDelete,
	"VMPTRST":markForDelete,
	"VMREAD":markForDelete,
	"VMRESUME":markForDelete,
	"VMRUN":markForDelete,
	"VMSAVE":markForDelete,
	"VMULPD":patternASSIGN_OR_ASSIGNC_12,
	"VMULPS":patternASSIGN_OR_ASSIGNC_12,
	"VMULSD":patternASSIGN_OR_ASSIGNC_12,
	"VMULSS":patternASSIGN_OR_ASSIGNC_12,
	"VMWRITE":markForDelete,
	"VMXOFF":markForDelete,
	"VMXON":markForDelete,
	"VORPD":patternASSIGN_OR_ASSIGNC_12,
	"VORPS":patternASSIGN_OR_ASSIGNC_12,
	"VPABSB":patternLIBCALL_OR_LIBCALLC_1,
	"VPABSD":patternLIBCALL_OR_LIBCALLC_1,
	"VPABSW":patternLIBCALL_OR_LIBCALLC_1,
	"VPACKSSDW":patternASSIGN,
	"VPACKSSWB":patternASSIGN,
	"VPACKUSDW":patternASSIGN,
	"VPACKUSWB":patternASSIGN,
	"VPADDB":patternASSIGN_OR_ASSIGNC_12,
	"VPADDD":patternASSIGN_OR_ASSIGNC_12,
	"VPADDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPADDSB":patternASSIGN_OR_ASSIGNC_12,
	"VPADDSW":patternASSIGN_OR_ASSIGNC_12,
	"VPADDUSW":patternASSIGN_OR_ASSIGNC_12,
	"VPADDW":patternASSIGN_OR_ASSIGNC_12,
	"VPALIGNR":patternASSIGN,
	"VPANDN":patternASSIGN_OR_ASSIGNC_12,
	"VPAND":patternASSIGN_OR_ASSIGNC_12,
	"VPAVGW":patternLIBCALL_OR_LIBCALLC_12,
	"VPBLENDVB":patternASSIGN,	
	"VPBLENDW":patternASSIGN,
	"VPCLMULQDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPCMPEQB":patternCONTROLC,
	"VPCMPEQW":patternCONTROLC,
	"VPCMPEQD":patternCONTROLC,
	"VPCMPEQQ":patternCONTROLC,
	"VPCMPESTRI":patternLIBCALL_OR_LIBCALLC_all,
	"VPCMPISTRI":patternLIBCALL_OR_LIBCALLC_all,
	"VPCMPESTRM":patternLIBCALL_OR_LIBCALLC_all,
	"VPCMPISTRM":patternLIBCALL_OR_LIBCALLC_all,
	"VPCMPGTB":patternCONTROLC,
	"VPCMPGTD":patternCONTROLC,
	"VPCMPGTQ":patternCONTROLC,
	"VPCMPGTW":patternCONTROLC,
	"VPERM2F128":patternASSIGN_OR_ASSIGNC_1,
	"VPERMILPD":patternASSIGN_OR_ASSIGNC_1,
	"VPERMILPS":patternASSIGN_OR_ASSIGNC_1,
	"VPEXTRB":patternLIBCALL_OR_LIBCALL_12,
	"VPEXTRD":patternLIBCALL_OR_LIBCALL_12,
	"VPEXTRQ":patternLIBCALL_OR_LIBCALL_12,
	"VPEXTRW":patternLIBCALL_OR_LIBCALL_12,
	"VPHADDD":patternASSIGN_OR_ASSIGNC_12,
	"VPHADDSW":patternASSIGN_OR_ASSIGNC_12,
	"VPHADDW":patternASSIGN_OR_ASSIGNC_12,
	"VPHMINPOSUW":patternLIBCALL_OR_LIBCALLC_12,
	"VPHSUBD":patternASSIGN_OR_ASSIGNC_12,
	"VPHSUBSW":patternASSIGN_OR_ASSIGNC_12,
	"VPHSUBW":patternASSIGN_OR_ASSIGNC_12,
	"VPINSRB":patternLIBCALL_OR_LIBCALLC_12,
	"VPINSRD":patternLIBCALL_OR_LIBCALLC_12,
	"VPINSRQ":patternLIBCALL_OR_LIBCALLC_12,
	"VPINSRW":patternLIBCALL_OR_LIBCALLC_12,
	"VPMADDUBSW":patternASSIGN_OR_ASSIGNC_12, 
	"VPMADDWD":patternASSIGN_OR_ASSIGNC_12,
	"VPMAX":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXSB":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXSD":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXSW":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXUB":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXUD":patternLIBCALL_OR_LIBCALLC_12,
	"VPMAXUW":patternLIBCALL_OR_LIBCALLC_12,
	"VPMIN":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINSB":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINSD":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINSW":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINUB":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINUD":patternLIBCALL_OR_LIBCALLC_12,
	"VPMINUW":patternLIBCALL_OR_LIBCALLC_12,
	"VPMOVMSKB":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXBD":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXBQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXBW":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXDQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXWD":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVSXWQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXBD":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXBQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXBW":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXDQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXWD":patternASSIGN_OR_ASSIGNC_1,
	"VPMOVZXWQ":patternASSIGN_OR_ASSIGNC_1,
	"VPMULDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPMULHRSW":patternASSIGN_OR_ASSIGNC_12,
	"VPMULHUW":patternASSIGN_OR_ASSIGNC_12,
	"VPMULHW":patternASSIGN_OR_ASSIGNC_12,
	"VPMULLD":patternASSIGN_OR_ASSIGNC_12,
	"VPMULLW":patternASSIGN_OR_ASSIGNC_12,
	"VPMULUDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPOR":patternASSIGN_OR_ASSIGNC_12,
	"VPSADBW":markForDelete,
	"VPSHUFB":markForDelete,
	"VPSHUFD":markForDelete,
	"VPSHUFHW":markForDelete,
	"VPSHUFLW":markForDelete,
	"VPSIGNB":markForDelete,
	"VPSIGND":markForDelete,
	"VPSIGNW":markForDelete,
	"VPSLLD":patternASSIGN_OR_ASSIGNC_12,
	"VPSLLDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPSLLQ":patternASSIGN_OR_ASSIGNC_12,
	"VPSLLW":patternASSIGN_OR_ASSIGNC_12,
	"VPSRAD":patternASSIGN_OR_ASSIGNC_12,
	"VPSRAW":patternASSIGN_OR_ASSIGNC_12,
	"VPSRLD":patternASSIGN_OR_ASSIGNC_12,
	"VPSRLDQ":patternASSIGN_OR_ASSIGNC_12,
	"VPSRLQ":patternASSIGN_OR_ASSIGNC_12,
	"VPSRLW":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBB":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBD":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBQ":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBSB":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBSW":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBUSB":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBUSW":patternASSIGN_OR_ASSIGNC_12,
	"VPSUBW":patternASSIGN_OR_ASSIGNC_12,
	"VPTEST":patternTEST_OR_TESTC_all,
	"VPUNPCKHQDQ":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKLQDQ":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKHBW":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKLBW":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKHWD":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKLWD":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKHDQ":patternLIBCALL_OR_LIBCALLC_12,
	"VPUNPCKLDQ":patternLIBCALL_OR_LIBCALLC_12,
	"VPXOR":patternASSIGN_OR_ASSIGNC_12,
	"VRCPPS":patternASSIGN_OR_ASSIGNC_argnum,
	"VRCPSS":patternASSIGN_OR_ASSIGNC_argnum,
	"VROUNDPD":patternLIBCALL_OR_LIBCALLC_1,
	"VROUNDPS":patternLIBCALL_OR_LIBCALLC_1,
	"VROUNDSD":patternLIBCALL_OR_LIBCALLC_1,
	"VROUNDSS":patternLIBCALL_OR_LIBCALLC_1,
	"VRSQRTPS":patternLIBCALL_OR_LIBCALLC_1,
	"VRSQRTSS":patternLIBCALL_OR_LIBCALLC_2,
	"VSHUFPD":markForDelete,
	"VSHUFPS":markForDelete,
	"VSQRTPD":patternLIBCALL_OR_LIBCALLC_1,
	"VSQRTPS":patternLIBCALL_OR_LIBCALLC_1,
	"VSQRTSD":patternLIBCALL_OR_LIBCALLC_2,
	"VSQRTSS":patternLIBCALL_OR_LIBCALLC_2,
	"VSTMXCSR":patternASSIGN_OR_ASSIGNC_0,
	"VSUBPD":patternASSIGN_OR_ASSIGNC_12,
	"VSUBPS":patternASSIGN_OR_ASSIGNC_12,
	"VSUBSD":patternASSIGN_OR_ASSIGNC_12,
	"VSUBSS":patternASSIGN_OR_ASSIGNC_12,
	"VTESTPD":patternTEST_OR_TESTC_all,
	"VTESTPS":patternTEST_OR_TESTC_all,
	"VUCOMISD":patternLIBCALL_OR_LIBCALLC_all,
	"VUCOMISS":patternLIBCALL_OR_LIBCALLC_all,
	"VUNPCKHPD":patternLIBCALL_OR_LIBCALLC_12,
	"VUNPCKHPS":patternLIBCALL_OR_LIBCALLC_12,
	"VUNPCKLPD":patternLIBCALL_OR_LIBCALLC_12,
	"VUNPCKLPS":patternLIBCALL_OR_LIBCALLC_12,
	"VXORPD":patternASSIGN_OR_ASSIGNC_12,
	"VXORPS":patternASSIGN_OR_ASSIGNC_12,
	"VZEROALL":markForDelete,
	"VZEROUPPER"markForDelete,
	"WAIT":markForDelete,
	"WBINVD":markForDelete,
	"WRFSBASE":patternASSIGN,
	"WRGSBASE":patternASSIGN,
	"WRMSR":patternASSIGN,
	"XADD":patternASSIGN_OR_ASSIGNC_all,
	"XCHG":patternASSIGN,
	"XGETBV":patternASSIGN,
	"XLAT":patternASSIGN,
	"XOR":patternASSIGN_OR_ASSIGNC_all,
	"XORPD":patternASSIGN_OR_ASSIGNC_all,
	"XORPS":patternASSIGN_OR_ASSIGNC_all,
	"XRSTOR":markForDelete,
	"XSAVE":markForDelete,
	"XSAVEOPT":markForDelete,
	"XSETBV":patternASSIGN,
	"3DNOW":markForDelete	}

	def __init__(self,addr,mnemonic,operands):
		self.addr = addr
		self.op = mnemonic
		self.operands = operands.split(',')
		Sentence.action[self.op](self)     #assigns a MAIL pattern to self statement

	def patternHALT(self):
		self.pattern = "HALT"

	def markForDelete(self):
		self.pattern = ""

	def patternFLAG(self):
		self.pattern = "FLAG"

	def patternLOCK(self):
		self.pattern = "LOCK"

	def patternSTACK(self):
		self.pattern = "STACK"

	def patternJUMPSTACK(self):
		self.pattern = "JUMPSTACK"

	def patternFLAGSTACK(self):
		self.pattern = "FLAGSTACK"

	def patternASSIGN(self):
		self.pattern = "ASSIGN"

	def patternASSIGNC(self):
		self.pattern = "ASSIGNC"

	def patternLIBCALL(self):
		self.pattern = "LIBCALL"

	def patternLIBCALLC(self):
		self.pattern = "LIBCALLC"

	def patternCONTROL(self):
		self.pattern = "CONTROL"

	def patternCONTROLC(self):
		self.pattern = "CONTROLC"

	def patternASSIGN_OR_ASSIGNC_0(self):
		if (self.operands[0].startswith("0x")):
			self.pattern = "ASSIGNC"
		else:
			self.pattern = "ASSIGN"

	def patternASSIGN_OR_ASSIGNC_1(self):
		if (self.operands[1].startswith("0x")):
			self.pattern = "ASSIGNC"
		else:
			self.pattern = "ASSIGN"


	def patternASSIGN_OR_ASSIGNC_2(self):
		if (self.operands[2].startswith("0x")):
			self.pattern = "ASSIGNC"
		else:
			self.pattern = "ASSIGN"



	def patternASSIGN_OR_ASSIGNC_all(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "ASSIGN"
		else:
			self.pattern = "ASSIGNC"

	def patternASSIGN_OR_ASSIGNC_12(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands[1:])
		if (len(const_operands) == 0):
			self.pattern = "ASSIGN"
		else:
			self.pattern = "ASSIGNC"

	def patternASSIGN_OR_ASSIGNC_argnum(self):
		if len(self.operands)==3:
			self.patternASSIGN_OR_ASSIGNC_2()
		else:
			self.patternASSIGN_OR_ASSIGNC_1()


	def patternJUMP_OR_JUMPC_0(self):
		if(self.operands[0].startswith("0x")):
			self.pattern = "JUMPC"
		else:
			self.pattern = "JUMP"

	def patternSTACK_OR_STACKC_0(self):
		if(self.operands[0].startswith("0x")):
			self.pattern = "STACKC"
		else:
			self.pattern = "STACK"


	def patternLIBCALL_OR_LIBCALLC_0(self):
		if(self.operands[0].startswith("0x")):
			self.pattern = "LIBCALLC"
		else:
			self.pattern = "LIBCALL"

	def patternLIBCALL_OR_LIBCALLC_1(self):
		if(self.operands[1].startswith("0x")):
			self.pattern = "LIBCALLC"
		else:
			self.pattern = "LIBCALL"

	def patternLIBCALL_OR_LIBCALLC_all(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "LIBCALL"
		else:
			self.pattern = "LIBCALLC"

	def patternLIBCALL_OR_LIBCALLC_12(self):
	const_operands = filter(lambda operand:operand.startswith("0x"), self.operands[1:])
		if (len(const_operands) == 0):
			self.pattern = "LIBCALL"
		else:
			self.pattern = "LIBCALLC"



	def patternCALL_OR_CALLC(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "CALL"
		else:
			self.pattern = "CALLC"

	def patternCONTROL_OR_CONTROLC_all(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "CONTROL"
		else:
			self.pattern = "CONTROLC"

	def patternTEST_OR_TESTC_all(self):
		const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if (len(const_operands) == 0):
			self.pattern = "TEST"
		else:
			self.pattern = "TESTC"

	#-----****-----
	def specialIMUL(self):
		if len(self.operands)==3:
			const_operands = filter(lambda operand:operand.startswith("0x"), self.operands[1:])
		else:
			const_operands = filter(lambda operand:operand.startswith("0x"), self.operands)
		if(len(const_operands)==0):
			self.pattern = "ASSIGN"
		else:
			self.pattern = "ASSIGNC"

	def specialJMP(self):
		idx = operand[0].index("0x")
		if (idx==0 or idx==1):
			self.pattern = "JUMPC"
		else:
			self.pattern = "JUMP"

	def specialJxxx(self):
		idx = operand[0].index("0x")
		if (idx==0 or idx==1):
			self.pattern = "CONTROLC"
		else:
			self.pattern = "CONTROL"













	def __repr__(self):
		return "%3s  :%15s %-10s" %(self.addr,self.op,self.operands)