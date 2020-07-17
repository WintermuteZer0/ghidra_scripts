# Highlights vulnerable functions in binary as potential areas of interest =
#@author Wintermute
#@category Vuln Helpers
#@keybinding
#@menupath
#@toolbar

'''
'''

from java.awt import Color

#Python simple console colour output class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



# RGB colors for target instructions
COLOR_TARGET = Color(255, 220, 220) #light red
COLOR_DEFAULT = Color(255,255,255) # white

list = (["strcpy","f__Strcmp", "strcpyA", "strcpyW", "wcscpy", "_tcscpy", "_mbscpy", "StrCpy",
       "StrCpyA", "StrCpyW", "lstrcpy", "lstrcpyA", "lstrcpyW", "_tccpy", "_mbccpy",
       "_ftcscpy", "strcat", "strcatA", "strcatW", "wcscat", "_tcscat", "_mbscat",
       "StrCat", "StrCatA", "StrCatW", "lstrcat", "lstrcatA", "lstrcatW", "StrCatBuff",
       "StrCatBuffA", "StrCatBuffW", "StrCatChainW", "_tccat", "_mbccat", "_ftcscat",
       "sprintfW", "sprintfA", "wsprintf", "wsprintfW", "wsprintfA", "sprintf", "swprintf",
       "_stprintf", "wvsprintf", "wvsprintfA", "wvsprintfW", "vsprintf", "_vstprintf",
       "vswprintf", "strncpy", "wcsncpy", "_tcsncpy", "_mbsncpy", "_mbsnbcpy", "StrCpyN",
       "StrCpyNA", "StrCpyNW", "StrNCpy", "strcpynA", "StrNCpyA", "StrNCpyW", "lstrcpyn",
       "lstrcpynA", "lstrcpynW", "strncat", "wcsncat", "_tcsncat", "_mbsncat", "_mbsnbcat",
       "StrCatN", "StrCatNA", "StrCatNW", "StrNCat", "StrNCatA", "StrNCatW", "lstrncat",
       "lstrcatnA", "lstrcatnW", "lstrcatn", "gets", "_getts", "_gettws", "IsBadWritePtr",
       "IsBadHugeWritePtr", "IsBadReadPtr", "IsBadHugeReadPtr", "IsBadCodePtr", "IsBadStringPtr"])


# search for target calls and apply color
instructions = currentProgram.getListing().getInstructions(True)

# get function manager for later function identification
fm = currentProgram.getFunctionManager()

for curInstr in instructions:
    TargetInstruction = False
    curMnem = curInstr.getMnemonicString().lower()
    
    # color call instructions
    if curMnem == 'call':
        numOperands = curInstr.getNumOperands()
        #refs= curInstr.getOperandReferences(numOperands)
        primSym = curInstr.getPrimarySymbol()
        #type = curInstr.getOperandType(1)

	flows = curInstr.getFlows()
        flow_type = curInstr.getFlowType()
        inputs = curInstr.getInputObjects()

        if len(flows)>0:
            # Get the called function symbol name
            func_flow = fm.getFunctionAt(flows[0])

            #Loop over list and compare
            for func in list:
                if(func in func_flow.getName()):
          
                    #Highlight with colour and print further output details 
                    TargetInstruction = True
                    setBackgroundColor(curInstr.getAddress(), COLOR_TARGET)
                    print('>>> Vuln func {} call found at {}'.format(func,curInstr.getAddress()))
                    print('>> Primary Symbol:: {}'.format(primSym))
                    print('>> Num of Operands:: {}'.format(numOperands))
                    print('>> Function Inputs:: {}'.format(inputs))
                    print('>> Flows to::{}'.format(func_flow.getName()))
                    print('>> Flows:: {}'.format(flows[0]))
                    print('>> Flow Types:: {}'.format(flow_type))
                    print('======================================================')

# Reset colour for non target instructions
    if TargetInstruction == False:
        setBackgroundColor(curInstr.getAddress(), COLOR_DEFAULT)




