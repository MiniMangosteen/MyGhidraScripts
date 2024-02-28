//目标函数参数的静态路径跟踪脚本
//@author hx
//@category 函数参数路径跟踪
//@keybinding
//@menupath 
//@toolbar 

import decompiler.DecompilerInitializer;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldRange;
import docking.widgets.fieldpanel.support.FieldSelection;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.ClangLayoutController;
import ghidra.app.decompiler.component.DecompileData;
import ghidra.app.decompiler.component.DecompilerManager;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.extension.datatype.finder.DecompilerDataTypeReferenceFinder;
import ghidra.app.extension.datatype.finder.DecompilerVariable;
import ghidra.app.merge.MergeManager;
import ghidra.app.merge.MergeProgressPanel;
import ghidra.app.script.GhidraScript;
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
import org.python.antlr.ast.Num;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

public class Dataflow extends GhidraScript {

    private static String targetFunction="vos_system";
    private  static DecompInterface decompInterfaces = null;
    private static int targetparmas=1;
    private static ArrayList<String> filterlist = new ArrayList<>();
    static {
        filterlist.add("main");
        filterlist.add("_start");
    }
    public void run() throws Exception {

        decompInterfaces = getDecompInterface();


        Filter(findCallFunctions(targetFunction), decompileResults -> {
            Horizontal_line(80);
            printf("\n\t\t\t [%s] 函数调用分析 \n\n\n",targetFunction);
            //decompileResults 是已经过滤出 无参和常量函数
            for (DecompileResults d : decompileResults) {
                printf("%s @ %s\n\n",d.getDecompiledFunction().getSignature(),d.getHighFunction().getFunction().getEntryPoint().toString());
                //函数调用栈输出
                //DisplayStack(d);
                printf("\n\n\n\n");
            }
            Horizontal_line(80);
            return false;
        });
        printf("\n");
    }


    private void Horizontal_line(int Count){
        for (int i = 0; i <Count; i++) {
            printf("-");
        }
    }

    //调用栈输出
    private void DisplayStack(DecompileResults decompileResults){
        ArrayList<ClangLine> clangLineArrayList =  DecompilerUtils.toLines(decompileResults.getCCodeMarkup());
        for (ClangLine cl : clangLineArrayList) {
            if (!cl.toString().contains(targetFunction+"("))
                continue;
            printf(" %s\n\n ",cl.toString()); //去掉行号
        }
        //回调函数
        Recursion(decompileResults.getHighFunction().getFunction(),getReferencesTo(decompileResults.getHighFunction().getFunction().getEntryPoint()),1);
    }


    private boolean Recursion(Function oldfunction,Reference[] references,int Number){
        if (references==null) return false;
        for (Reference ref : references) {
            Function function = getFunctionContaining(ref.getFromAddress());
            if (function!=null){
               if (!filterlist.contains(function.getName())){
                   DecompileResults results = decompInterfaces.decompileFunction(function, 0, getMonitor());
                   if (results.getHighFunction().getLocalSymbolMap().getNumParams()!=0) {       //递归过滤出无参函数
                       if (Prints(oldfunction.getName(),results,Number))
                            Recursion(function,getReferencesTo(function.getEntryPoint()), Number + 1);   //递归
                   }else return false;
               }
            }
        }
        return true;
    }




    //过滤出参数为常量的调用栈
    private boolean FilterParams(String oldName,DecompileResults results){
        ArrayList<ClangLine> clangLineArrayList =  DecompilerUtils.toLines(results.getCCodeMarkup());
        for (ClangLine cl: clangLineArrayList){
            if (!cl.toString().contains(oldName+"("))
                continue;
            printf(" |-> %s  \n\n",results.getHighFunction().getFunction().getName());
            return true;
        }
        return false;
    }

    private boolean Prints(String name,DecompileResults results,int Number){
        for (int i = 0; i < Number; i++)
            printf("\t");
        return FilterParams(name,results);
        //return true;
    }

    private void Filter(ArrayList<Function> refxlist,Callback callback){
        ArrayList<DecompileResults> decompileResults = new ArrayList<>();
        for (Function f : refxlist) {
            DecompileResults results = decompInterfaces.decompileFunction(f, 0, getMonitor());
            //1.过滤无参数
            if (results.getHighFunction().getLocalSymbolMap().getNumParams() != 0){
                Iterator<PcodeOpAST> opASTIterator = results.getHighFunction().getPcodeOps();
                while (opASTIterator.hasNext()){
                    PcodeOp pcodeOp = opASTIterator.next();
                    if (pcodeOp.getOpcode()==PcodeOp.CALL){
                        if (getFunctionName(pcodeOp.getInput(0).getAddress()).equals(targetFunction)){
                            //2.过滤常量参数
                            if (!pcodeOp.getInput(1).isUnique())
                                if (!decompileResults.contains(results))
                                    decompileResults.add(results);
                        }
                    }
                }
            }
        }
        //3.调用栈与参数链跟踪处理
        if (!decompileResults.isEmpty())
            callback.Control(decompileResults);
        else printerr("Err！");
    }



    interface Callback{
        boolean Control(ArrayList<DecompileResults> decompileResults);
    }
    interface Stack{
        boolean MethodStack();
    }

    private String getFunctionName(Address funAddress){
        return getFunctionAt(funAddress).getName();
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


    //目标函数的交叉引用
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
