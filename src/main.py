import r2pipe as r2
import json
import os
import sys
import cPickle
from Function import FunctionCFG, Sentence, functionComparator


#---------------------------------------------------------------------------------
#-------training------------------------------------------------------------------

def store_signature(malware_filename):
	r2p 	= r2.open("../malwares/"+malware_filename)
	r2p.cmd("aaa")
	func_list = json.loads(r2p.cmd("aflj"))
	signature = [FunctionCFG(func,r2p) for func in func_list]
	
	sig_file  = open("../signatures/SIG_"+malware_filename,"wb")
	cPickle.dump(signature,sig_file,protocol=cPickle.HIGHEST_PROTOCOL)
	sig_file.close()

def train():
	count =1
	for malware_filename in os.listdir("../malwares/"):
		sig_path = '../signatures/SIG_'+malware_filename
		print str(count)+" : " +malware_filename +" storing SIGNATURE"
		if (os.path.exists(sig_path)):
			print "...But this Signature has already been stored !"
			continue
		try:
			store_signature(malware_filename)
			count = count+1
		except Exception as e:
			if (os.path.exists(sig_path)):
				os.remove(sig_path)

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
			print "\n--CHECKING WITH :"+sig_filename
			print "\n-- #functions   :"+str(len(malware_signature))
			print "\n-- #functions in Sample:"+str(len(signature))
			for funcCFG_S in signature:
				if len(funcCFG_S.blockDisassembly)==1:
					continue
				for funcCFG_M in malware_signature:
					if(functionComparator(funcCFG_S,funcCFG_M)):
						count = count+1
						break
					if(count > threshold):
						print "COUNT="+str(count) +" fucntions' CFGs have matched"
						return True

		except Exception as e:
			print "exception occurred"
			raise e
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