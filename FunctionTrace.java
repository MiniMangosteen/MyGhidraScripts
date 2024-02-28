//查找函数参数交叉链接
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ServiceListener;
import ghidra.pcodeCPort.pcoderaw.VarnodeData;
import ghidra.pcodeCPort.slghsymbol.VarnodeListSymbol;
import ghidra.program.model.graph.GraphData;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.util.VarnodeContext;
import ghidra.util.Msg;
import ghidra.util.exception.NotFoundException;

import java.util.*;


public class FunctionTrace extends GhidraScript {

    private String sinkFunctionName="vos_system";
    private DecompInterface decompInterface=null;
    private static String PROGRAM_NAME = "deobHookExample";

    // Heap allocation area
    private static final int MALLOC_REGION_SIZE = 0x1000;

    // Address used as final return location
    private static final long CONTROLLED_RETURN_OFFSET = 0;

    // Function locations
    private Address mainFunctionEntry; // start of emulation
    private Address controlledReturnAddr; // end of emulation


    // Important breakpoint locations for hooking behavior not contained with binary (e.g., dynamic library)
    private Address mallocEntry;
    private Address freeEntry;
    private Address strlenEntry;
    private Address useStringEntry;

    private ServiceListener serviceListener = new ServiceListener() {

        @Override
        public void serviceRemoved(Class<?> interfaceClass, Object service) {
            if (interfaceClass.equals(GraphService.class)) {
                //graphServiceRemoved();
            }
        }

        @Override
        public void serviceAdded(Class<?> interfaceClass, Object service) {
            if (interfaceClass.equals(GraphService.class)) {
                //graphServiceAdded();
                printf("MyServer\n");
            }
        }
    };

    public void run() throws Exception {

        DecompInterface ifc = getDecompInterface();
        decompInterface = ifc;

        Address target_add = getSymbolAddress("main");
        printf("%s\n",getFunctionContaining(target_add).getName());
        Address target_addT = getExternalThunkAddress(sinkFunctionName);
        printf("%s\n",getFunctionContaining(target_addT).getName());
        Reference[] references =  getReferencesTo(target_addT);

        FunctionIterator functionIterator =  currentProgram.getListing().getFunctions(true);
        while (functionIterator.hasNext()){
            Function function = functionIterator.next();
            if (function.getName().equals("FUN_00077370")){
                DecompileResults results =  decompInterface.decompileFunction(function,0,getMonitor());
                HighFunction highFunction = results.getHighFunction();
                LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
                printf("\t 形参数： %d \n",localSymbolMap.getNumParams());
                printf("\t FUN_00077370 %d\n",highFunction.getNumVarnodes());
            }
            if (function.getName().equals("clear_tmp_file")){
                DecompileResults results =  decompInterface.decompileFunction(function,0,getMonitor());
                HighFunction highFunction = results.getHighFunction();
                Iterator<VarnodeAST> iterator = highFunction.locRange();
                ReferenceManager referenceManager = currentProgram.getReferenceManager();
                while (iterator.hasNext()){
                    VarnodeAST varnodeAST = iterator.next();

                    /*
                    printf("\t %s \n",varnodeAST.toString());
                    if (varnodeAST.getDef()!=null){
                        printf("\t |->%s \n",varnodeAST.getDef().toString());
                    }
                     */



                    if (varnodeAST.getHigh()!=null)
                        printf("\t %s |-> %s %s\n",varnodeAST.getHigh().getName(),varnodeAST.toString(),varnodeAST.getDef()!=null ? varnodeAST.getDef().toString():"null");
                }

                LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
                printf("\t 形参数： %d \n",localSymbolMap.getNumParams());
                printf("\t clear_tmp_file %d\n",highFunction.getNumVarnodes());
            }
        }
    }


    private DecompInterface getDecompInterface() throws DecompileException {
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(this.getCurrentProgram())) {
            throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
        }

        return ifc;
    }


    private Address getAddress(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }



    private Address getExternalThunkAddress(String symbolName) throws NotFoundException {
        Symbol externalSymbol = currentProgram.getSymbolTable().getExternalSymbol(symbolName);
        if (externalSymbol != null && externalSymbol.getSymbolType() == SymbolType.FUNCTION) {
            Function f = (Function) externalSymbol.getObject();
            Address[] thunkAddrs = f.getFunctionThunkAddresses();
            if (thunkAddrs.length == 1) {
                return thunkAddrs[0];
            }
        }
        throw new NotFoundException("Failed to locate label: " + symbolName);
    }


    private Address getSymbolAddress(String symbolName) throws NotFoundException {
        Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(currentProgram, symbolName,
                err -> Msg.error(this, err));
        if (symbol != null) {
            return symbol.getAddress();
        }
        throw new NotFoundException("Failed to locate label: " + symbolName);
    }


    private ArrayList<Function> findCallFunctions(String targetName){
        FunctionIterator iterator=currentProgram.getListing().getFunctions(true);
        ArrayList<Function> arrayList = new ArrayList<>();
        Function function;
        Reference[] references;
        while(iterator.hasNext()){
            function = iterator.next();
            if (function.getName().equals(targetName)){
                references = getReferencesTo(function.getEntryPoint());
                for (Reference referenceFunction : references) {
                    Function callFromFunction =  getFunctionContaining(referenceFunction.getFromAddress());
                    if (callFromFunction!=null && !callFromFunction.isThunk() && !arrayList.contains(callFromFunction)){
                        arrayList.add(callFromFunction);
                    }
                }
            }
        }
        return arrayList;
    }


}
