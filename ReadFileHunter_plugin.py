import json 
import sys 

try:
    args = getScriptArgs()
    response_dict = dict()

    if len(args) < 1:
        print("usage: ./FunctionsList.py output_path")
        sys.exit(0)

    # output_path of the json file (should terminate with ".json")
    output_path = args[0]
    functions_dict = dict()
    
    # search for target calls
    instructions = currentProgram.getListing().getInstructions(True)

    # get function manager for later function identification
    fm = currentProgram.getFunctionManager()

    for curInstr in instructions:
        curMnem = curInstr.getMnemonicString().lower()

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

