import r2pipe as r2
import json
import os
import sys
import cPickle
from Function import FunctionCFG, Sentence, functionComparator


#---------------------------------------------------------------------------------
#-------training------------------------------------------------------------------

def store_signature(malware_filename):
	r2p 	= r2.open("../malwares2/"+malware_filename)
	r2p.cmd("aaa")
	func_list = json.loads(r2p.cmd("aflj"))
	signature = [FunctionCFG(func,r2p) for func in func_list]
	
	sig_file  = open("../signatures/SIG_"+malware_filename,"wb")
	cPickle.dump(signature,sig_file)
	sig_file.close()

def train():
	count =1
	for malware_filename in os.listdir("../malwares2/"):
		print str(count)+" : " +malware_filename +" storing SIGNATURE"
		store_signature(malware_filename)

#----------------------------------------------------------------------------------
#--------testing-------------------------------------------------------------------
def checkIfMalware(testsample_filename,threshold):
	r2p 	= r2.open("../testsamples/"+testsample_filename)
	r2p.cmd("aaa")
	func_list = json.loads(r2p.cmd("aflj"))
	signature = [FunctionCFG(func,r2p) for func in func_list]
	
	for sig_filename in os.listdir("../signatures/"):
		try:
			sig_file = open("../signatures/"+sig_filename,"rb")
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
		if(checkIfMalware("../testsamples/"+testsample_filename,threshold)):
			print testsample_filename+" is a MALWARE!"



if __name__ == '__main__':
	if len(sys.argv) < 3:
		print "USAGE: python "+sys.argv[0]+" < TRAIN/TEST >  <NONE/threshold>\n\n"
		sys.exit()

	if(sys.argv[1].strip().upper() == "TRAIN"):
		train()
	elif(sys.argv[1].strip().upper() == "TEST"):
		threshold = int(sys.argv[2])
		test(threshold)