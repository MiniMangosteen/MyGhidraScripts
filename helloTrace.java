//TODO vos_system 函数参数的跟踪
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import org.python.antlr.ast.Pass;

import java.util.*;

public class helloTrace extends GhidraScript {

    private DecompInterface decomplib;
    private String sinkFunctionName="vos_system";
    private HashMap<String,ArrayList<String>> ConstValue = new HashMap<>();
    private HashMap<String,Function> RegsValue = new HashMap<>();
    public void run() throws Exception {


        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");
        if (!ifc.openProgram(this.getCurrentProgram())) {
            throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
        }
        Language language = currentProgram.getLanguage();       //language 返回架构x86、arm、arm64
        AddressSetView set = currentProgram.getMemory().getExecuteSet();
        Listing listing = currentProgram.getListing();
        SymbolTable symbolTable =  currentProgram.getSymbolTable();
        FunctionIterator fi = listing.getFunctions(true);
        ArrayList<Function> callFunctions = findCallFunctions(fi,sinkFunctionName);
        for (Function fromFunction : callFunctions) {
            //多次调用的情况
            ArrayList<PcodeOpAST> callSites = getFunctionCallPcodeOpAST(ifc,fromFunction);
            //printerr("Call @@ "+fromFunction.getName());
            ArrayList<String> constvalue = new ArrayList<>();
            for (PcodeOpAST callSite : callSites) {
                analyzeFunctionCallSite(fromFunction,callSite,constvalue);
            }
            if (!constvalue.isEmpty())
                ConstValue.put(fromFunction.getName(),constvalue);
            else
                RegsValue.put(fromFunction.getName(),fromFunction);
        }
        //println("--------------------------------------------");
        SplitLine(180,"常量");
        for (Map.Entry<String, ArrayList<String>> entry : ConstValue.entrySet()) {
            printerr("Call @@ "+entry.getKey()+"\n\t |");
            for (String value : entry.getValue()) {
                printf("\t |-> %s ",value);
            }
            printf("\n");
        }

        //println("--------------------------------------------");
        SplitLine(180,"预测量");
        for (Map.Entry<String,Function> entr: RegsValue.entrySet()){
            printerr("Call @@ "+entr.getKey());
            Function function = entr.getValue();
            ArrayList<PcodeOpAST> callSites = getFunctionCallPcodeOpAstReg(ifc,function);
            analyzeFunctionCallSiteRegs(function,callSites);
        }
        printf("\n");
        for (Function fromFunction : callFunctions) {
            DisplayFromFunction(fromFunction,0);
            printf("\n");
        }





    }//end run

    private void DisplayFromFunction(Function fromFunction,int i){
        Reference[] references = getReferencesTo(fromFunction.getEntryPoint());
        analyzeReference(references);
        printf("|->  %s\n",fromFunction.getName());
    }

    private void analyzeReference(Reference[] reference){
        if (reference==null) return;
        for (Reference re : reference) {
            Function callFromFunction = getFunctionContaining(re.getFromAddress());
            if (callFromFunction!=null && !callFromFunction.isThunk()){
                Reference[] references = getReferencesTo(callFromFunction.getEntryPoint());
                if (references!=null){
                    analyzeReference(references);
                }
                printf("|->  %s",callFromFunction.getName());
            }

        }
    }




    private void analyzeFunctionCallSiteRegs(Function callFunction,ArrayList<PcodeOpAST> astArrayList){

        ArrayList<PcodeOpAST> target = new ArrayList<>();
        ArrayList<PcodeOpAST> Assist = new ArrayList<>();
        for (PcodeOpAST pcode : astArrayList) {

            if (getFunctionAt(pcode.getInput(0).getAddress()).getName().contains(sinkFunctionName)){
                target.add(pcode);
            }
            if (getFunctionAt(pcode.getInput(0).getAddress()).getName().contains("snprintf_s")){
                Assist.add(pcode);
            }
        }

        for (PcodeOpAST Passist : Assist) {

           if (Passist.getInput(1).isRegister()){

               for (PcodeOpAST Ptarget : target) {

                   if (Ptarget.getInput(1).isRegister()){

                       if (Passist.getInput(1).toString().equals(Ptarget.getInput(1).toString())){
                           //printf("\n[%s] %s <---> [%s] %s\n",getFunctionAt(Passist.getInput(0).getAddress()).getName(),Passist.getInput(1).toString(),getFunctionAt(Ptarget.getInput(0).getAddress()).getName(),Ptarget.getInput(1).toString());
                           ParsPcode(Passist,Ptarget);
                            break;
                       }
                   }
               }
           }
        }


        //

        printf("\n");
    }

    private void ParsPcode(PcodeOpAST pcodeOpAST,PcodeOpAST opAST){
        printf("\t\n |-> %s (",getFunctionAt(opAST.getInput(0).getAddress()).getName());
        int Number = pcodeOpAST.getNumInputs();
        for (int i = 0; i < Number; i++) {
            ParsValue(pcodeOpAST.getInput(i));
        }
        printf(")\n");

    }


    private void ParsValue(Varnode varnode){
        if (varnode.isRegister()){
            printf(" %s ",varnode.toString(currentProgram.getLanguage()));
        }else if (varnode.isConstant()){
            printf(", %s ",varnode.toString(currentProgram.getLanguage()));
        }else if(varnode.isUnique()){
            try {
                String val = ParsUnique(varnode);
                if (val!=null) printf(", %s ",val.trim());
            } catch (MemoryAccessException e) {
                e.printStackTrace();
            }
        }
    }

    private String ParsUnique(Varnode varnode) throws MemoryAccessException {
        String retvalue=null;
        PcodeOp pcodeOp = varnode.getDef();
        switch (pcodeOp.getOpcode()){
            case PcodeOp.COPY:
                Data val = getDataAt(toAddr(pcodeOp.getInput(0).getOffset()));
                retvalue = new String(val.getBytes());
                break;
            case PcodeOp.INT_2COMP:
                retvalue = pcodeOp.getInput(0).toString();
                break;
            case PcodeOp.INT_RIGHT:
                retvalue = pcodeOp.getInput(0).toString();
                break;
            case PcodeOp.PTRSUB:
                retvalue = pcodeOp.getInput(0).toString(currentProgram.getLanguage());
                break;
            default:
                printf("\n %s ",pcodeOp.toString());
                printerr("err.\n");
        }
        return retvalue;
    }



    private void analyzeFunctionCallSite(Function callFunction,PcodeOpAST pcodeOpAST,ArrayList<String> values){

        int number=pcodeOpAST.getNumInputs();
        for (int i=0;i<number;i++){
            Varnode varnode = pcodeOpAST.getInput(i);
            if (varnode.isAddress()){
                //printf("[%s] -> [%s]:",varnode.getAddress().toString(),getFunctionAt(varnode.getAddress()).getName());
                callFunction.getName();
            }
            if (varnode.isUnique()){
                PcodeOp var = varnode.getDef();
                if (var.getInput(0).isConstant()){
                    long off = var.getInput(0).getOffset();
                    Data str = getDataAt(toAddr(off));
                    try {
                        //printf(" %s (\" %s \")\t\n",sinkFunctionName,new String(str.getBytes()).trim());
                        values.add(String.format(" %s (\" %s \")\t\n",sinkFunctionName,new String(str.getBytes()).trim()));
                    } catch (MemoryAccessException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }


    private ArrayList<PcodeOpAST> getFunctionCallPcodeOpAstReg(DecompInterface decompInterface,Function deFunction){

        ArrayList<PcodeOpAST> callSite = new ArrayList<>();
        HighFunction highFunction = DecompileFunction(decompInterface,deFunction);
        Iterator<PcodeOpAST> opASTIterator = highFunction.getPcodeOps();
        while (opASTIterator.hasNext()){
            PcodeOpAST opAST = opASTIterator.next();
            if (opAST.getOpcode() == PcodeOp.CALL){
                Varnode calledVarnode = opAST.getInput(0);
                if (calledVarnode == null || !calledVarnode.isAddress())
                    continue;

                String funName = getFunctionAt(calledVarnode.getAddress()).getName();
                if (funName.contains(sinkFunctionName)){
                    callSite.add(opAST);
                }else if (funName.contains("snprintf_s")){
                    callSite.add(opAST);
                }
            }
        }
        return callSite;
    }


    private ArrayList<PcodeOpAST> getFunctionCallPcodeOpAST(DecompInterface decompInterface,Function deFunction){
        //println("Call @@ ["+deFunction+"]");
        ArrayList<PcodeOpAST> callSite = new ArrayList<>();
        HighFunction highFunction = DecompileFunction(decompInterface,deFunction);
        Iterator<PcodeOpAST> opASTIterator =  highFunction.getPcodeOps();
        while(opASTIterator.hasNext()){
            PcodeOpAST opAST = opASTIterator.next();
            if (opAST.getOpcode()==PcodeOp.CALL){
                Varnode calledVarnode = opAST.getInput(0);//地址
                if (calledVarnode==null || !calledVarnode.isAddress()){
                    continue;
                }
                String funName = getFunctionAt(calledVarnode.getAddress()).getName();
                if (funName.contains(sinkFunctionName)){
                    //printf("[%s] -> [%s] \n",calledVarnode.getAddress().toString(),funName);
                    callSite.add(opAST);
                }
            }
        }
       return callSite;
    }

    private HighFunction DecompileFunction(DecompInterface decompInterface,Function target){
        HighFunction highFunction = null;
        DecompileResults results =  decompInterface.decompileFunction(target,60,monitor);
        highFunction = results.getHighFunction();
        results.getDecompiledFunction();//返回C函数
        return highFunction;
    }

    private ArrayList<Function> findCallFunctions(FunctionIterator iterator, String targetName){
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


    private void SplitLine(int len,String message){
        for (int i = 0; i < len; i++) {
            printf("-");
            if ((i>0) && (i%(len/2)==0)){
                printf("[%s]",message);
            }
        }
        printf("\n");
    }

    /*
	set up the decompiler
	*/
    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();
        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, program);
            }
        }
        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        return decompInterface;
    }


    public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, String calledFunctionName){

        ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();

        HighFunction hfunction = decompileFunction(f);
        if(hfunction == null) {
            printf("ERROR: Failed to decompile function!\n");
            return null;
        }

        Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

        //iterate over all p-code ops in the function
        while (ops.hasNext() && !monitor.isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {

                //current p-code op is a CALL
                //get the address CALL-ed
                Varnode calledVarnode = pcodeOpAST.getInput(0);

                if (calledVarnode == null || !calledVarnode.isAddress()) {
                    printf("ERROR: call, but not to address!");
                    continue;
                }

                //if the CALL is to our function, save this callsite
                if( getFunctionAt(calledVarnode.getAddress()).getName().compareTo(calledFunctionName) == 0) {
                    pcodeOpCallSites.add(pcodeOpAST);
                }
            }
        }
        return pcodeOpCallSites;

    }

    public HighFunction decompileFunction(Function f) {
        HighFunction hfunction = null;

        try {
            DecompileResults dRes = decomplib.decompileFunction(f, 60, null);

            hfunction = dRes.getHighFunction();
        }
        catch (Exception exc) {
            printf("EXCEPTION IN DECOMPILATION!\n");
            exc.printStackTrace();
        }

        return hfunction;
    }

}
