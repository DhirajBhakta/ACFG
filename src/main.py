import angr
import os
import cPickle
from Function import FunctionCFG, Sentence




def store_signature(malware_filename,sig_file):
	malware_filename = "../malwares/"+malware_filename
	b 	= angr.Project(malware_filename)
	cfg = b.analyses.CFGFast()
	FM  = cfg.functions
	signature = [FunctionCFG(func) for func in FM.itervalues()]
	cPickle.dump(signature,sig_file)



def main():
	sig_file = open("malware_signatures","wb")
	for malware_filename in os.listdir("../malwares/"):
		store_signature(malware_filename,sig_file)






if __name__ == '__main__':
	main()