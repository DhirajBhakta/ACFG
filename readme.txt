POSSIBLE POINTS OF FAILURE:
1) i've given just one pattern for complex ASM statements that break down to multiple MAIL statements, ; the paper requires each MAIL stmt to be given a pattern, but ive given just one pattern to the whole thing.

eg: XCHG : is broken down into 3 assignment MAIL statements.
	   so the pattern must be "ASSIGN","ASSIGN","ASSIGN"
	   But ive just given ASSIGN once....
	   
	   
	   
	   
2) block address?.-- are ALL of them INT ? check all places where block addresses are used.
	especially in FunctionCFG(instance).blockDisassembly[block.addr] 
	and,..... is it really "address" or "addr" . 
	
	>>for capstone its "address"
	>>for block its "addr"
