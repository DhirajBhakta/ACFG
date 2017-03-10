import angr

#GOAL : To Construct CFGs of every function within the malware binary .
#       And then convert each line in each CFG (of every function) to an intermediate Language
#       And store the signature of the Malware in  the form of a list of CFGs , along with the intermediate representation of each line  



b = angr.Project("malwareBinary")

cfg = b.analyses.CFGFast()

FuncMgr = cfg.kb.functions

for func in FuncMgr.itervalues():
	print "FUNCTION NAME:"+func.name 
	print "TOTAL BLOCKS :"+str(sum([1 for x in func.blocks]))
	for block in func.blocks:
		print block.pp()
		print "|"
		print "|"
		print "|"
		print "v"
	print "----------------------------------------------------"
	print "end of Function"
	print "----------------------------------------------------"

