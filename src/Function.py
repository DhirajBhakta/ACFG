import networkx as nx
import pygraphviz
import re
from patterns import *





class FunctionCFG:

	p 	 = re.compile("^.*0x[a-f0-9]+ {6}.*$")
	p_comments = re.compile(";.*")
	p_OP = re.compile("([0-9a-f\.]+ {1,}){2}")

	def __init__(self,function,r2p):
	#	self.function = function
		r2p.cmd("ag "+str(function['offset'])+">a.dot")
		self.graph = nx.nx_agraph.read_dot("a.dot")
		self.blockDisassembly = {}
		self.parseAllBlocks(function,r2p)

	
	@staticmethod
	def getInsns(line):
		if not (FunctionCFG.p.match(line)):
			return None
		else:
			line = FunctionCFG.p_OP.sub("",line.partition("0x")[-1])
			insn = (FunctionCFG.p_comments.sub("",line)).strip()
			return insn


	def parseAllBlocks(self,function,r2p):
		for block_addr in self.graph.node.keys():
			block_dismbl = r2p.cmd("pdb @"+str(int(block_addr,16)))
			block_dismbl = block_dismbl.splitlines()
			block_dismbl = map(FunctionCFG.getInsns, block_dismbl)
			block_dismbl = filter(None,block_dismbl)
			#block_dismbl = map(utf8,block_dismbl)
			sentences = list()
			
					

			
			sentences = filter(lambda sentence:sentence.pattern!=None, sentences)
			self.blockDisassembly[block_addr]=sentences



#-------------------------------------------------------------------------------------
#funcS	:FunctionCFG instance of a Test 'S'ample
#funcM	:FunctionCFG instance of a 'M'alware 
#functionComparator checks if a Sample FunctionCFG matches(subgraph isomorphically) a Malware FunctionCFG
def functionComparator(funcS,funcM):
	graph_matcher = nx.isomorphism.DiGraphMatcher(funcS.graph,funcM.graph)
	if(graph_matcher.subgraph_is_isomorphic()):
		for blockS_addr,blockM_addr in graph_matcher.mapping.items():
			for sentenceS,sentenceM in zip(funcS.blockDisassembly[blockS_addr],funcM.blockDisassembly[blockM_addr]):
				if sentenceS.pattern != sentenceM.pattern:
					return False
		return True

	else:
		return False
#-------------------------------------------------------------------------------------






class Sentence:
	
	def __init__(self,OPstring):
		partition = OPstring.split(' ',1)
		self.opcode = partition[0].strip()
		self.operands = []
		if len(partition)>1:
			self.operands = [operand.strip() for operand in partition[1].split(',')]

		if action.has_key(self.opcode.upper()):
			try:
				action[self.opcode.upper()](self)     #assigns a MAIL pattern to self statement
			except Exception as e: 
				raise e
				print self.__repr__()
		else:
			self.pattern = "UNKNOWN"
	
	def __repr__(self):
		return "%3s  :%15s %-10s" %(self.addr,self.op,self.operands)