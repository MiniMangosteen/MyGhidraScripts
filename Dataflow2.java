// 函数参数静态数据流跟踪
//@author hx
//@category 参数流跟踪第2版本
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


//1.脚本是否通用
//2.参数是char*、数组和堆类型需要跟踪数据组合，参数int、float、double就要找调用栈来源
//3.过滤规则是否有一致性
//4.界面增加复杂化还是简单化

public class Dataflow2 extends GhidraScript {

    public void run() throws Exception {

        if (!CheckInput()){
            Horizontal_line(80);
            printerr("输入错误，脚本结束运行！");
            Horizontal_line(80);
            return;
        }

        decompInterfaces = getDecompInterface();
        Filter(findCallFunctions(targetFunction), decompileResults -> {
            Horizontal_line(80);
            printf("\n\t\t\t [%s] 函数调用分析 \n\n\n",targetFunction);
            //decompileResults 是已经过滤出 无参和常量函数
            for (DecompileResults d : decompileResults) {
                //输出target在代码中的行号位置
                if (P_codeFilter(d)){
                    printf(" [==>] %s @ %s\n\n",d.getDecompiledFunction().getSignature(),d.getHighFunction().getFunction().getEntryPoint().toString());
                    DisplayTarget(d);
                }
                printf("\n\n\n\n");
            }
            Horizontal_line(80);
            return false;
        });
        printf("\n");
    }

    //******************************************************************************************************************
    // 指针类型参数过滤,需要分析参数的组合过程，判断组合过程是否是常量 system字符串过滤方法，                  【不通用】
    //******************************************************************************************************************
    private boolean P_codeFilter(DecompileResults decompileResults){
        printf("%s\n",decompileResults.getHighFunction().getFunction().getName());
        ArrayList<PcodeBlockBasic> pcodeBlockBasics = decompileResults.getHighFunction().getBasicBlocks();
        for (PcodeBlockBasic pcodeBlockBasic :pcodeBlockBasics) {
            //printf("%s => %d\n",pcodeBlockBasic.getStart().toString(),pcodeBlockBasic.getIndex());
            Iterator<PcodeOp>  iterator = pcodeBlockBasic.getIterator();
            while (iterator.hasNext()){
                PcodeOp op = iterator.next();
                if (op.getOpcode()==PcodeOp.CALL){
                    if (getFunctionName(op.getInput(0).getAddress()).equals(targetFunction)){
                        printf("  %s %s \n\n",op.toString(),op.getInput(TargetParam).toString(currentProgram.getLanguage()));
                        //如果参数为常量则跳过
                        if (op.getInput(TargetParam).isUnique())
                            continue;
                        //反向开始查找
                        if (ReverseInquire(pcodeBlockBasic.getIndex(),pcodeBlockBasics,op.getInput(TargetParam).toString(currentProgram.getLanguage())))
                            return true;
                        //没有参数组合的情况
                        if (op.getInput(TargetParam).isAddrTied())
                            return true;
                    }
                }
            }
        }
        return false;
    }

    //******************************************************************************************************************
    // 反向循环遍历查找目标参数组合                                                                       【通用型过滤】
    //******************************************************************************************************************
    private boolean ReverseInquire(int index,ArrayList<PcodeBlockBasic> arrays,String reg){
        for (int i = index; i > -1 ; i--) {
            Iterator<PcodeOp> opIterator = arrays.get(i).getIterator();
            while (opIterator.hasNext()){
                PcodeOp oop = opIterator.next();
                if(Options(oop,reg))
                    return true;
            }
        }
        return false;
    }

    //******************************************************************************************************************
    // 处理P-code编码
    //******************************************************************************************************************
    private boolean Options(PcodeOp op,String reg){

        switch (op.getOpcode()){
            case PcodeOp.CALL:
                return OptionCall(op,reg);
            case PcodeOp.COPY:
                return OptionCopy(op,reg);
            default:
                break;
        }
        return false;
    }

    //******************************************************************************************************************
    // 处理参数组合函数
    //******************************************************************************************************************
    private boolean OptionCall(PcodeOp op,String reg){

        switch (getFunctionName(op.getInput(0).getAddress())){
            case "sprintf":
                return CheckSprintf(op,reg);
            case "snprintf_s":
                return CheckSprintf_f(op,reg);
            case "snprintf":
                return CheckSnprintf(op,reg);
            case "vsnprintf":
                return CheckVsnprintf(op,reg);
            default:
                return false;
        }
    }

    private boolean CheckSprintf(PcodeOp op,String reg){
        printf("Sprintf %s %s\n\n",op.toString(),op.getInput(1).toString(currentProgram.getLanguage()));

        //判断format是否为空
        if (op.getInput(1).toString(currentProgram.getLanguage()).equals(reg)){
            printf("Sprintf %s %s\n\n",op.toString(),op.getInput(1).toString(currentProgram.getLanguage()));
            if (Pattterns(getDataAt(toAddr(op.getInput(2).getDef().getInput(0).getOffset())).toString())!=null)
                //判断format是否存在%s
                if (Pattterns(getDataAt(toAddr(op.getInput(2).getDef().getInput(0).getOffset())).toString()).equals(FORMAT))
                    //判断最后参数是否常量
                    //if (!op.getInput(op.getNumInputs()-1).isUnique())

                    return true;

        }else {

        }
        return false;
    }

    private boolean CheckSprintf_f(PcodeOp op,String reg){
        //printf("Sprintf_f\n");
        //printf("\t%s \n",getFunctionName(op.getInput(0).getAddress()));
        if (op.getInput(1).toString(currentProgram.getLanguage()).equals(reg)){
            if (Pattterns(getDataAt(toAddr(op.getInput(4).getDef().getInput(0).getOffset())).toString())!=null)
                if (Pattterns(getDataAt(toAddr(op.getInput(4).getDef().getInput(0).getOffset())).toString()).equals(FORMAT))
                    //if (!op.getInput(op.getNumInputs()-1).isUnique())
                        //printf("\t%s \n",Pattterns(getDataAt(toAddr(op.getInput(4).getDef().getInput(0).getOffset())).toString()));
                    return true;
        }
        return false;
    }

    private boolean CheckSnprintf(PcodeOp op,String reg){

        //printf("snprintf %s %s\n\n",op.toString(),op.getInput(1).toString(currentProgram.getLanguage()));
        if (op.getInput(1).toString(currentProgram.getLanguage()).equals(reg)){

            if (Pattterns(getDataAt(toAddr(op.getInput(3).getDef().getInput(0).getOffset())).toString())!=null)
                if (Pattterns(getDataAt(toAddr(op.getInput(3).getDef().getInput(0).getOffset())).toString()).equals(FORMAT))
                    //if (!op.getInput(op.getNumInputs()-1).isUnique())
                    printf("snprintf %s %s\n\n",op.toString(),op.getInput(1).toString(currentProgram.getLanguage()));
                    return true;
        }

        return false;
    }

    private boolean CheckVsnprintf(PcodeOp op,String reg){

        return true;
    }

    private boolean OptionCopy(PcodeOp op,String par){
        return false;
    }

    //******************************************************************************************************************
    // 递归输出targetFunction调用栈，递归中无参数函数过滤                                                  【通用型过滤】
    //******************************************************************************************************************
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

    //******************************************************************************************************************
    // 过滤交叉引用函数调用targetFunction时传入的值是常量或者是本身函数是没有参数的                            【通用型过滤】
    //******************************************************************************************************************
    private void Filter(ArrayList<Function> refxlist, Dataflow.Callback callback){
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
                                //3.list表中过滤重复
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
        else printerr(targetFunction+" 索引为null！");
    }

    //******************************************************************************************************************
    // 查找 targetName 的交叉引用                                                                       【通用型过滤】
    //******************************************************************************************************************
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


    //******************************************************************************************************************
    // 获取 DecompInterface 对象
    //******************************************************************************************************************
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

    //******************************************************************************************************************
    // 非逻辑函数
    //******************************************************************************************************************

    private void Horizontal_line(int Count){
        for (int i = 0; i <Count; i++)
            printf("-");
        printf("\n");
    }

    interface Callback{
        boolean Control(ArrayList<DecompileResults> decompileResults);
    }

    private boolean isLess(int Number1,int Number2){
        if (Number1 == Number2)
            return true;
        printerr("跟踪数大于函数本身参数，请重新填写！");
        return false;
    }

    private String getFunctionName(Address funAddress){
        return getFunctionAt(funAddress).getName();
    }

    private boolean Prints(String oldName,DecompileResults results,int Number){
        for (int i = 0; i < Number; i++)
            printf("\t");
        return FilterParams(oldName,results);
        //return true;
    }

    private boolean CheckInput(){
        if (targetFunction!=null && ParamCount!=0 && ParamType!=0&& TargetParam!=0){
            if (TargetParam <= ParamCount)
                return true;
        }
        return false;
    }

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

    private void DisplayTarget(DecompileResults decompileResults){
        ArrayList<ClangLine> clangLineArrayList =  DecompilerUtils.toLines(decompileResults.getCCodeMarkup());
        for (ClangLine cl : clangLineArrayList) {
            if (cl.toString().contains(targetFunction+"(")){
                printf(" %s\n\n ",cl.toString());
            }
        }
        //Recursion(decompileResults.getHighFunction().getFunction(),getReferencesTo(decompileResults.getHighFunction().getFunction().getEntryPoint()),1);
    }

    private String Pattterns(String compiles){
        printf("%s\n",compiles);
        Pattern pattern = Pattern.compile(".(%.)");
        Matcher matcher = pattern.matcher(compiles);
        if (matcher.find())
            return matcher.group(1);

        return null;
    }

    //******************************************************************************************************************
    // 参数定义
    //******************************************************************************************************************
    private static String targetFunction="vos_system";      //跟踪的参数名
    private static int ParamCount= 1;                    //参数个数
    private static int ParamType = 1;                   //参数类型
    private static int TargetParam=1;                   //跟踪参数
    private static String FORMAT="%s";                  //格式化字符串
    private  static DecompInterface decompInterfaces = null;
    private static ArrayList<String> filterlist = new ArrayList<>();
    private static ArrayList<String> listfun = new ArrayList<>();
    static {
        filterlist.add("main");
        filterlist.add("_start");
        listfun.add("snprintf_s");
        listfun.add("strncpy_s");
    }

}
