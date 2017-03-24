import r2pipe as r2
import pygraphviz
import networkx as nx 
import json
import re

def utf8(str):
	return str.encode("utf-8")



p_comments = re.compile(";.*")
p_bar = re.compile("|")
p_desc = re.compile("\(.*\)")
p_final = re.compile("([0-9a-f\.]+ {1,}){2}")


def getOpcodeOperands(line):
	partition = line.split(' ',1)
	opcode = partition[0]
	if len(partition)>1 :
		operands = partition[1].split(',')
	else:
		operands = []	
	print "OPCODE:"+opcode+"    OPERANDS:"+str(operands)


def printblock(block,n):
	print "----------------------------------NEW BLOCK---"+str(n)+"-----------------------------------------------------"
	for line in block:
		line=p_comments.sub("",line)
		line=p_bar.sub("",line)
		if(p_desc.search(line)):
			line = ""
		else:
			line = p_final.sub("",line.partition("0x")[-1])
			getOpcodeOperands(line)
	print "\n\n\n\n"


# counts actual number of lines in a block
def lines(block):
	count = 0
	p = re.compile("^.*0x[a-f0-9]+ {6}.*$")
	for line in block:
		if p.match(line):
			print p.match(line)
			count+=1
	return count


#---------------------------------------------------------------------------------
#---------------------------------------------------------------------------------
r2p = r2.open("virus")
r2p.cmd("aaa")

fn_list = json.loads(r2p.cmd("aflj"))
for fn in fn_list:
	r2p.cmd("ag "+str(fn['offset'])+">a.dot")
	G = nx.nx_agraph.read_dot("a.dot")
	for block_addr in G.node.keys():
		block_dismbl = r2p.cmd("pdb @"+str(int(block_addr,16)))
		block_dismbl = block_dismbl.splitlines()
		block_dismbl = map(utf8,block_dismbl)
		n = lines(block_dismbl)
		printblock(block_dismbl,n)
      