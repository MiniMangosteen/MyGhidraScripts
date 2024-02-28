//TODO 函数参数跟踪
//@author 
//@category P-CODE
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

public class vos_system extends GhidraScript {




    private String sinkFunctionName="read";
    private DecompInterface decompInterface=null;
    ArrayList<String> NotAvailable = new ArrayList<>();
    ArrayList<String> NotPar = new ArrayList<>();
    //不可利用Not available
    //fit
    File f = new File("/Volumes/Mac/MyTools/ghidra_9.1.2_PUBLIC","trace.txt");
    public void run() throws Exception {

        DecompInterface ifc = getDecompInterface();
        decompInterface = ifc;

        ArrayList<Function> filterList = FilterFun(findCallFunctions(sinkFunctionName), new FilterConst() {
            @Override
            public boolean isExp(Function function) {
                boolean isExp=false;
                Iterator<PcodeOpAST>  iterator =  getDecompileFunctionPcodes(function);
                while (iterator.hasNext()){
                    PcodeOp pcodeOp=iterator.next();
                    if (pcodeOp.getOpcode() == PcodeOp.CALL &&
                    getFunctionName(pcodeOp.getInput(0).getAddress()).equals(sinkFunctionName)){
                        //printf("\t %s -> %s\n",function.getName(),pcodeOp.toString());
                        if (pcodeOp.getInput(1).isRegister())
                            isExp=true;
                        if (pcodeOp.getInput(1).isUnique()){
                            isExp=false;
                            long off = pcodeOp.getInput(1).getDef().getInput(0).getOffset();
                            Data data = getDataAt(toAddr(off));
                            try {
                                NotAvailable.add(String.format("\t[%s] -> %s(\" %s \")\n",function.getName(),sinkFunctionName,new String(data.getBytes()).trim()));
                            } catch (MemoryAccessException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
                return isExp;
            }
        });

        printerr("\t 未确定");
        analyzeFunction(filterList, new AnalyzeTrace() {
            @Override
            public boolean isTrace(Function function, String r0_reg) {
                Iterator<PcodeOpAST> astIterator = getDecompileFunctionPcodes(function);
                while (astIterator.hasNext()) {
                    PcodeOpAST pcodeOpAST = astIterator.next();
                    if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {
                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals(sinkFunctionName))
                            continue;
                        if (pcodeOpAST.getNumInputs() > 4 && pcodeOpAST.getInput(1).toString(currentProgram.getLanguage()).equals(r0_reg)) {
                            //printf("\t %s \n", pcodeOpAST.toString());
                           String codestring =  displayPcodeOpAST(pcodeOpAST);
                           printf("\t %s \n",codestring);
                        }
                    }
                }
                return false;
            }

            @Override
            public String displayPcodeOpAST(PcodeOpAST pcodeOpAST) {
                StringBuilder builder = new StringBuilder();

                Varnode[] varnodes = pcodeOpAST.getInputs();
                for (Varnode v : varnodes) {
                    if (v.isAddress()){
                        builder.append(String.format("\t\t |-> %s (",getFunctionName(v.getAddress())));
                    }
                    if (v.isRegister()){
                        builder.append(String.format(" %s ",v.toString(currentProgram.getLanguage())));
                    }
                    if (v.isConstant()){
                        builder.append(String.format(" %s ",v.toString(currentProgram.getLanguage())));
                    }
                    if (v.isUnique()){
                        PcodeOp pcodeOp = v.getDef();
                        switch (pcodeOp.getOpcode()){
                            case PcodeOp.COPY:
                                Data data = getDataAt(toAddr(pcodeOp.getInput(0).getOffset()));
                                try {
                                    builder.append(String.format(" %s ",new String(data.getBytes()).trim()));
                                 } catch (MemoryAccessException e) {
                                    e.printStackTrace();
                                }
                                break;
                            case PcodeOp.PTRSUB:
                                builder.append(String.format(" %s ",pcodeOp.toString()));
                                break;
                        }
                    }
                  // builder.append(String.format("%s",v.toString()));
                } //end for
                builder.append(")\n");
                return builder.toString();
            }
        });


        printerr("\t 函数调用栈");
        analyzeReferences(filterList, new DisplayReferences() {
            @Override
            public void displayReferences(Reference[] references,int Number,String funName) {
                if (references==null) return;
                for (Reference re : references) {
                    Function function = getFunctionContaining(re.getFromAddress());
                    if (function!=null){
                        Prints(function, funName, Number, new AnalyzeFunction() {
                            @Override
                            public String displayfunctionAST(Function function,String oldFun) {
                                if (function.getName().equals("main"))
                                    return "";
                                if (function.getName().equals("_start"))
                                    return "";
                                Iterator<PcodeOpAST>  iterator =  getDecompileFunctionPcodes(function);
                                while (iterator.hasNext()){
                                    PcodeOpAST pcodeOpAST = iterator.next();
                                    if (pcodeOpAST.getOpcode()==PcodeOp.CALL){
                                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals(oldFun)){
                                           //return displayPcodeOpAST(pcodeOpAST,oldFun);
                                            return displayRegDef(displayPcodeOpAST(pcodeOpAST,oldFun),function,oldFun,pcodeOpAST.getInputs());
                                        }
                                    }
                                }
                                return "";
                            }

                            @Override
                            public StringBuilder displayPcodeOpAST(PcodeOpAST pcodeOpAST,String oldFun) {
                                StringBuilder builder = new StringBuilder();
                                builder.append(String.format(" Call @@ "));
                                Varnode[] varnodes = pcodeOpAST.getInputs();
                                for (Varnode v : varnodes) {

                                    if (v.isAddress()){
                                        builder.append(String.format(" %s (",getFunctionName(v.getAddress())));
                                    }
                                    if (v.isRegister()){
                                        builder.append(String.format(" %s, ",v.toString(currentProgram.getLanguage())));
                                    }
                                    if (v.isConstant()){
                                        builder.append(String.format(" %s, ",v.toString(currentProgram.getLanguage())));
                                    }
                                    if (v.isUnique()){
                                        PcodeOp pcodeOp = v.getDef();
                                        switch (pcodeOp.getOpcode()){
                                            case PcodeOp.COPY:
                                                Data data = getDataAt(toAddr(pcodeOp.getInput(0).getOffset()));
                                                try {
                                                    builder.append(String.format(" %s, ",new String(data.getBytes()).trim()));
                                                } catch (MemoryAccessException e) {
                                                    e.printStackTrace();
                                                }
                                                break;
                                            case PcodeOp.PTRSUB:
                                                builder.append(String.format(" %s, ",pcodeOp.toString()));
                                                break;
                                        }
                                    }
                                    if (v.isFree()){
                                        //builder.append(String.format(" %s, ",v.toString()));
                                    }
                                    if (v.isHash()){
                                        builder.append(" isHash, ");
                                    }
                                    if (v.isInput()){
                                        builder.append(" isInput, ");
                                    }
                                    if (v.isPersistant()){
                                        builder.append(" isPersistant, ");
                                    }
                                    if (v.isUnaffected()){
                                        builder.append(" isUnaffected, ");
                                    }
                                    if (v.isAddrTied()){
                                        builder.append(String.format(" %s, ",v.toString(currentProgram.getLanguage())));
                                    }
                                    // builder.append(String.format("%s",v.toString()));
                                } //end for
                                //return new StringBuilder("");
                                return  builder.append(")");
                                //return builder.toString();
                            }

                            @Override
                            public String displayRegDef(StringBuilder CallMethod, Function function, String oldFun,Varnode[] varnodes) {

                                CallMethod.append("\n\t");
                                ArrayList<String> RegList= new ArrayList<>();
                                for (Varnode v : varnodes) {
                                    //CallMethod.append(String.format("%s",v.toString()));
                                }


                                return CallMethod.toString();
                            }
                        });
                        displayReferences(getReferencesTo(function.getEntryPoint()),Number+1,function.getName());
                    }
                }
            }
        });

        printerr("\t 参数不可控");
        for (String p : removeDuplicate_2(NotPar)) {
            printf("%s", p);
        }
        printerr("\t 常量参数");
        if (NotAvailable.isEmpty())
            printf("\tnull\n");
        for (String p : NotAvailable) {
            printf("%s", p);
        }

    }

    private void Prints(Function function,String message,int Number,AnalyzeFunction analyzeFunction){
        for (int i = 0; i < Number; i++) {
            printf("\t");
        }
        printf("|-> %s  %s\n\n",function.getName(),analyzeFunction.displayfunctionAST(function,message));
    }

    private void analyzeReferences(ArrayList<Function> filterList,DisplayReferences displayReferences){

        for (Function fun : filterList) {
            printerr(fun.getName()+"\n");
            displayReferences.displayReferences(getReferencesTo(fun.getEntryPoint()),2,fun.getName());
        }
    }


    private void analyzeFunction(ArrayList<Function> filterList,AnalyzeTrace analyzeTrace){

        for (Function fun : filterList) {
            printf("\n\t %s \n",fun.getName());
            Iterator<PcodeOpAST> iterator = getDecompileFunctionPcodes(fun);
            while(iterator.hasNext()){
                PcodeOpAST opAST = iterator.next();
                if (opAST.getOpcode()==PcodeOp.CALL && getFunctionName(opAST.getInput(0).getAddress()).equals(sinkFunctionName)){
                    printf("\t\t |-> %s (%s)\n",getFunctionName(opAST.getInput(0).getAddress()),opAST.getInput(1).toString(currentProgram.getLanguage()));
                    analyzeTrace.isTrace(fun,opAST.getInput(1).toString(currentProgram.getLanguage()));
                }
            }
        }

    }

    private Iterator<PcodeOpAST> getDecompileFunctionPcodes(Function target){
        DecompileResults results =  decompInterface.decompileFunction(target,0,getMonitor());
        HighFunction highFunction = results.getHighFunction();
        results.getDecompiledFunction();//返回C函数
        return highFunction.getPcodeOps();
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

    private ArrayList<Function> FilterFun(ArrayList<Function> functionArrayList,FilterConst filterConst){

        ArrayList<Function> filterFunctions = new ArrayList<>();
        Reference[] references;
        boolean isFind=false;
        for (Function func : functionArrayList) {
            //printerr("Call @@ "+func.getName());
            references = getReferencesTo(func.getEntryPoint());
            for (Reference referenceFunction : references) {
                Function callFromFunction = getFunctionContaining(referenceFunction.getFromAddress());
               if (callFromFunction!=null &&
               !callFromFunction.isThunk()){
                   if (analyzePar(callFromFunction,func.getName())){
                       //存在一个函数被调用多次，所以需要使用list来过滤重复的调用函数
                       //printf("\t -%s \n",callFromFunction.getName());
                       if (!filterFunctions.contains(func)&&filterConst.isExp(func)){
                           filterFunctions.add(func);

                       }
                   }
               }
            }
        }
        return filterFunctions;
    }

    private boolean analyzePar(Function callFromFunction,String targetName){
        boolean isNotPar=false;
        Iterator<PcodeOpAST> opASTIterator = getDecompileFunctionPcodes(callFromFunction);
        while(opASTIterator.hasNext()){
            PcodeOpAST opAST = opASTIterator.next();
            if (opAST.getOpcode()==PcodeOp.CALL  &&
            getFunctionName(opAST.getInput(0).getAddress()).equals(targetName)){
                //printf("\t -%s \n",callFromFunction.getName());
                if (opAST.getNumInputs()>1){
                    isNotPar = true;
                    break;
                }
                NotPar.add(String.format("\t %s \n",targetName));

            }
        }
        return isNotPar;
    }

    private static ArrayList<String> removeDuplicate_2(ArrayList list){
        HashSet set = new HashSet(list);
        //使用LinkedHashSet可以保证输入的顺序
        //LinkedHashSet<String> set2 = new LinkedHashSet<String>(list);
        list.clear();
        list.addAll(set);
        return list;
    }


    private String getFunctionName(Address funAddress){
        return getFunctionAt(funAddress).getName();
    }


    interface DisplayReferences{
        void displayReferences(Reference[] references,int Number,String oldFun);
    }

    interface AnalyzeTrace{
        boolean isTrace(Function function,String r0_reg);
        String displayPcodeOpAST(PcodeOpAST pcodeOpAST);
    }

    interface FilterConst{
        boolean isExp(Function function);
    }

    interface AnalyzeFunction{
        String displayfunctionAST(Function function,String oldFun);
        StringBuilder displayPcodeOpAST(PcodeOpAST pcodeOpAST,String olfFun);
        String displayRegDef(StringBuilder CallMethod, Function function, String oldFun,Varnode[] varnodes);
    }
}
