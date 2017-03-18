import angr
import os
import sys
import cPickle
from Function import FunctionCFG, Sentence, functionComparator


#---------------------------------------------------------------------------------
#-------training------------------------------------------------------------------

def store_signature(malware_filename,sig_file):
	proj 	= angr.Project(malware_filename)
	cfg = proj.analyses.CFGFast()
	FM  = cfg.functions
	signature = [FunctionCFG(func) for func in FM.itervalues()]
	cPickle.dump(signature,sig_file)



def train():
	sig_file = open("malware_signatures","wb")
	for malware_filename in os.listdir("../malwares/"):
		store_signature("../malwares/"+malware_filename,sig_file)

#----------------------------------------------------------------------------------
#--------testing-------------------------------------------------------------------
def checkIfMalware(testsample_filename,threshold):
	proj = angr.Project(testsample_filename)
	cfg  = proj.analyses.CFGFast()
	FM = cfg.functions
	signature = [FunctionCFG(func) for func in FM.itervalues()]
	sig_file = open("malware_signatures","rb")
	while(True):
		try:
			malware_signature = cPickle.load(sig_file)
			count=0
			for funcCFG_S in signature:
				for funcCFG_M in malware_signature:
					if(functionComparator(funcCFG_S,funcCFG_M)):
						count = count+1
					if(count > threshold):
						print "COUNT="+str(count) +" fucntions' CFGs have matched"
						return True

		except (EOFError, UnpicklingError):
			break
	return False




def test(threshold):
	for testsample_filename in os.listdir("../testsamples/"):
		checkIfMalware("../testsamples/"+testsample_filename,threshold)



if __name__ == '__main__':
	if len(sys.argv) < 3:
		print "USAGE: python "+sys.argv[0]+" < TRAIN/TEST >  <NULL/threshold>\n\n"
		sys.exit()

	if(sys.argv[1].strip().upper() == "TRAIN"):
		train()
	elif(sys.argv[1].strip().upper() == "TEST"):
		threshold = int(sys.argv[2])
		test(threshold)