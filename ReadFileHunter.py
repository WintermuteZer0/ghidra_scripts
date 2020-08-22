# Identifies ReadFile calls for further inspection in fuzzing targets =
#@author Wintermute
#@category Vuln Helpers
#@keybinding
#@menupath
#@toolbar

# search for target calls
instructions = currentProgram.getListing().getInstructions(True)

# get function manager for later function identification
fm = currentProgram.getFunctionManager()


#Decopilier
#decompiler= openProgram(currentProgram)

#def decompileFunction(f):
##    try:
 #       ddRes = decompileFunction(f)
 #       #hfunction = ddRes.getHighFunction()
 #       #return hfunction
 #   except Exception as exc:
 #       print("EXCEPTION IN DECOMPILATION!: {}\n".format(exc))



##for function in fm.getFunctions(True):
 #   if 'ReadFile' in function.getName():
 #       refs = getReferencesTo(function.getEntryPoint())
 #       for ref in refs:
 #           if('CALL' in ref.getReferenceType().getName()):
 #               caller = fm.getFunctionContaining(ref.getFromAddress())
 #               #decFunc = decompileFunction(caller)
 #               print('>> Found ReadFile Ref at {}, called at {} from {}'.format(function.getEntryPoint().getOffset(),ref.getFromAddress().getOffset(),ref.getReferenceType().getName()))
                #if(decFunc):
                 #   ops = decFunc.getPcodeOps()
                 #   print(ops)
                 #   print('>> ReadFile called by {}'.format(caller.getName()))
                



for curInstr in instructions:
    TargetInstruction = False
    curMnem = curInstr.getMnemonicString().lower()
    
   # color call instructions
    if curMnem == 'call':
        numOperands = curInstr.getNumOperands()
        primSym = curInstr.getPrimarySymbol()

	flows = curInstr.getFlows()
        flow_type = curInstr.getFlowType()
        inputs = curInstr.getInputObjects()

        if len(flows)>0:
            # Get the called function symbol name
            func_flow = fm.getFunctionAt(flows[0])
            if 'ReadFile' in func_flow.toString():
                caller = fm.getFunctionContaining(curInstr.getAddress())
                print('>>> Found a ReadFile call: Caller: {}, Address: {}, Flow Target: {}, Call Type: {}'.format(caller.getName(),curInstr.getAddress(),func_flow.getName(),flow_type))
                #print('>>> Caller Paramters: {}'.format(caller.getParameters()))
                print('[*] InputObjects: {}'.format(curInstr.getInputObjects()))
                print('[*] Caller Details: Address: {}\n[*] Signature: {}\n[*] Prototype: {}'.format(caller.getEntryPoint(),caller.getSignature(True), caller.getPrototypeString(True,True)))

