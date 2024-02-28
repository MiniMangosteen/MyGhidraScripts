// 函数参数静态数据流跟踪
//@author hx
//@category 参数流跟踪第3版本
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Dataflow3 extends GhidraScript {

    public void run() throws Exception {

        if (!CheckInput()){
            Horizontal_line(80);
            printerr("输入错误，脚本结束运行！");
            Horizontal_line(80);
            return;
        }

        Horizontal_line(80);
        printf(" \t\t %s \n",targetFunction);
        Horizontal_line(80);

        decompInterfaces = getDecompInterface();
        SecondFilter(FirstFilter(findCallFunctions(targetFunction)),decompInterfaces-> {
            //只做输出
        });

        printf("\n");
    }

    //******************************************************************************************************************
    // 指针类型参数过滤,需要分析参数的组合过程，判断组合过程是否是常量 system字符串过滤方法，                  【不通用】
    //******************************************************************************************************************
    private boolean P_codeFilter(DecompileResults decompileResults){
        //printf(" [==>] %s @ %s\n\n",decompileResults.getDecompiledFunction().getSignature(),decompileResults.getHighFunction().getFunction().getEntryPoint().toString());
        ArrayList<PcodeBlockBasic> pcodeBlockBasics = decompileResults.getHighFunction().getBasicBlocks();
        int OldIndex=-1,count=0,isTrue=0,Num=0;
        for (PcodeBlockBasic pcodeBlockBasic :pcodeBlockBasics) {
            Iterator<PcodeOp>  iterator = pcodeBlockBasic.getIterator();
            while (iterator.hasNext()){
                PcodeOp op = iterator.next();
                if ((op.getOpcode()==PcodeOp.CALL) && getFunctionName(op.getInput(0).getAddress()).equals(targetFunction)){
                    if (op.getInput(1).isRegister()){
                    //if (true){
                        count=0;
                        for (int i = pcodeBlockBasic.getIndex(); i > OldIndex ; i--) {
                            Iterator<PcodeOp> opIterator = pcodeBlockBasics.get(i).getIterator();
                            while (opIterator.hasNext()){
                                PcodeOp oop = opIterator.next();
                                switch (oop.getOpcode()){
                                    case PcodeOp.CALL:      //参数组合情况
                                        switch (getFunctionName(oop.getInput(0).getAddress())){
                                            case "sprintf":
                                                //count++;
                                                  if (CheckSprintf(oop,op))
                                                      isTrue++;
                                                      //return true;
                                                  break;
                                            case "snprintf_s":
                                                //count++;
                                                if (CheckSnprintf_s(oop,op))
                                                     isTrue++;
                                                    //return true;
                                                break;
                                            case "snprintf":
                                                //count++;
                                                if ( CheckSnprintf(oop,op))
                                                     isTrue++;
                                                    //return true;
                                                break;
                                            case "vsnprintf":
                                                //count++;
                                                if (CheckVsnprintf(oop,op))
                                                     isTrue++;
                                                    //return true;
                                                break;
                                            default:
                                               continue;
                                        }
                                        break;
                                    default:
                                        //参数没有组合的情况
                                        if (count==0)
                                            Num++;
                                }
                            }
                        }
                        OldIndex = pcodeBlockBasic.getIndex();
                    }else {
                        if (op.getInput(1).getDef()!=null){
                            if (op.getInput(1).getDef().getOpcode()==PcodeOp.COPY)
                                return false;
                            return true;
                        }
                    }
                }
            }
        }
        printf("count:%d , isTrue:%d , Num:%d\n",count,isTrue,Num);
        if (isTrue!=0&&count!=0)
            return true;
        else if (Num!=0)
            return  true;
        return false;
    }


    private boolean Loop(Iterator<PcodeOp>  iterator,ArrayList<PcodeBlockBasic> pcodeBlockBasics,PcodeBlockBasic pcodeBlockBasic){
        int OldIndex=-1;
        while (iterator.hasNext()){
            PcodeOp op = iterator.next();
            if (op.getOpcode()==PcodeOp.CALL){
                if (getFunctionName(op.getInput(0).getAddress()).equals(targetFunction)){   //target寻找
                    if (op.getInput(1).isRegister()){
                        if (ReverseInquire(pcodeBlockBasic.getIndex(),pcodeBlockBasics,op,OldIndex))
                            return true;
                        OldIndex = pcodeBlockBasic.getIndex();
                    }else {
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
    private boolean ReverseInquire(int index,ArrayList<PcodeBlockBasic> arrays,PcodeOp op,int len){
        for (int i = index; i > len ; i--) {
            Iterator<PcodeOp> opIterator = arrays.get(i).getIterator();
            while (opIterator.hasNext()){
                if(Options(opIterator.next(),op))
                    return true;
            }
        }
        return false;
    }


    //******************************************************************************************************************
    // 处理P-code编码
    //******************************************************************************************************************
    private boolean Options(PcodeOp op,PcodeOp oldop){

        switch (op.getOpcode()){
            case PcodeOp.CALL:
                return OptionCall(op,oldop);
            default:
                break;
        }
        return false;
    }

    //******************************************************************************************************************
    // 处理参数组合函数
    //******************************************************************************************************************
    private boolean OptionCall(PcodeOp op,PcodeOp oldop){

        switch (getFunctionName(op.getInput(0).getAddress())){
            case "sprintf":
                return CheckSprintf(op,oldop);
            case "snprintf_s":
                return CheckSnprintf_s(op,oldop);
            case "snprintf":
                return CheckSnprintf(op,oldop);
            case "vsnprintf":
                return CheckVsnprintf(op,oldop);
            default:
                break;
        }
        return false;
    }
    private boolean OptionCopy(PcodeOp op,PcodeOp oldop){

        return false;
    }

    //sprintf
    private boolean CheckSprintf(PcodeOp op,PcodeOp oldop){
        //printf("\t [sprintf] %s %d\n",getDataAt(toAddr(op.getInput(2).getDef().getInput(0).getOffset())),op.getNumInputs());
        if (CheckReg(op,oldop))
            if (CheckParam(op,2))
                return true;

        LogText(op,oldop);
        return false;
    }
    //sprintf_f
    private boolean CheckSnprintf_s(PcodeOp op, PcodeOp oldop){
        //printf("\t[sprintf_s] %s %d\n",getDataAt(toAddr(op.getInput(4).getDef().getInput(0).getOffset())),op.getNumInputs());
        if (CheckReg(op,oldop))
            if (CheckParam(op,4))
                return true;
        return false;
    }

    //snprintf
    private boolean CheckSnprintf(PcodeOp op,PcodeOp oldop){
        //printf("\t[snprintf] %s %d\n",getDataAt(toAddr(op.getInput(3).getDef().getInput(0).getOffset())),op.getNumInputs());
        if (CheckReg(op,oldop))
            if (CheckParam(op,3))
                return true;
        LogText(op,oldop);
        return false;
    }

    //vsnprintf     不处理
    private boolean CheckVsnprintf(PcodeOp op,PcodeOp oldop){
        //printf("[vsnprintf] 不处理\n");
        LogText(op,oldop);
        return true;
    }

    //format判断后面参数是否为常量
    private boolean CheckParam(PcodeOp op,int index){
        //printf("%s\n",op.getInput(index).getDef());

        try {   // 工具不识别数据类型时 保护操作


            if (op.getInput(index).getDef()==null) return true;

            if (op.getInput(index).getDef().getOpcode()==PcodeOp.MULTIEQUAL) return true;

            //printf("%s\n",op.toString());
            ArrayList<String> stringArrayList = Pattterns(getDataAt(toAddr(op.getInput(index).getDef().getInput(0).getOffset())).toString());
            //printf("%s %d %s\n",getDataAt(toAddr(op.getInput(index).getDef().getInput(0).getOffset())).toString(),matcher.groupCount(),matcher.group(0));
            if (!stringArrayList.isEmpty()){
                int count=0,isUni=0;
                for (int i = 0; i < stringArrayList.size(); i++) {
                    switch (stringArrayList.get(i)){
                        case "%s":
                            count++;
                            if (op.getInput(index+1+i).isUnique())
                                if (op.getInput(index+1+i).getDef().getOpcode()==PcodeOp.COPY)  //继续排除运行式的Unique
                                    isUni++;
                            //printf("[s] %s\n",op.getInput(index+1+i).getDef().toString());
                            //printf("[s] %s\n",getDataAt(toAddr(op.getInput(index+1+i).getDef().getInput(1).getOffset())));
                            break;
                        case "%d":
                            count++;
                            //printf("[d] %s\n",op.getInput(index+1+i).toString());
                            break;
                        default:
                            if (count==0)
                                count++;

                    }
                }
                if (count==0)
                    return false;

                if ((count>0 && isUni>0) && (isUni == count)) {
                    return false;
                }

            }else {
                //printf("is null\n");
                return false;
            }
        }catch (Exception e){
            printf("[-] 函数分析错误！\n");
            return true;
        }
        //printf("=====\n");
        return true;
    }

    private boolean CheckReg(PcodeOp op,PcodeOp oldop){
        if (op.getInput(1).getDef()==null) return true;
        if (op.getInput(1).getDef().getOpcode()==PcodeOp.PTRSUB &&
            oldop.getInput(1).getDef().getOpcode()==PcodeOp.PTRSUB)
        {
           if (op.getInput(1).getDef().getInput(0).contains(oldop.getInput(1).getDef().getInput(0).getAddress()))
               if (op.getInput(1).getDef().getInput(1).contains(oldop.getInput(1).getDef().getInput(1).getAddress())){
                   LogText(op,oldop);
                   return true;
               }

        }else {

            if (op.getInput(1).toString(currentProgram.getLanguage()).equals(oldop.getInput(1).toString(currentProgram.getLanguage())))
                return true;
        }
        return false;
    }

    private void LogText(PcodeOp op, PcodeOp oldop){
        if (true) return;
        printf("\t\t %s ==> %s <==> %s\n",getFunctionName(op.getInput(0).getAddress()),op.getInput(1).toString(),op.getInput(1).getDef());
        printf("\t\t %s ==> %s <==> %s\n",getFunctionName(oldop.getInput(0).getAddress()),oldop.getInput(1).toString(),oldop.getInput(1).getDef());
    }




    //1.寄存器相同
    //2.结构体相同
    //3.格式化字符来判断后面参数类型
    //4.无参数组合情况

    //******************************************************************************************************************
    // 二次过滤函数内target组合参数情况                                                                  【定制不通用】
    //******************************************************************************************************************
    private void SecondFilter(ArrayList<DecompileResults> decompileResultsArrayList,Callback callback){
        int count=0;
        ArrayList<DecompileResults> filterarraylist = new ArrayList<>();
        for (DecompileResults d : decompileResultsArrayList) {
            if (P_codeFilter(d)){
                count++;
                printf(" [=======>] %s @ %s\n\n",d.getDecompiledFunction().getSignature(),d.getHighFunction().getFunction().getEntryPoint().toString());
                filterarraylist.add(d);
            }
        }
        printf("\t 总计：%d\n",count);
    }


    //******************************************************************************************************************
    // 过滤交叉引用函数调用targetFunction时传入的值是常量或者是本身函数是没有参数的                            【通用型过滤】
    //******************************************************************************************************************
    private ArrayList<DecompileResults> FirstFilter(ArrayList<Function> refxlist){
        ArrayList<DecompileResults> decompileResults = new ArrayList<>();
        for (Function f : refxlist) {
            DecompileResults results = decompInterfaces.decompileFunction(f, 0, getMonitor());
            //printf("[-] %s  \n",results.getHighFunction().getFunction().getName());
            //1.过滤无参数
            //if (results.getHighFunction().getLocalSymbolMap().getNumParams() != 0){
            if (true){
                Iterator<PcodeOpAST> opASTIterator = results.getHighFunction().getPcodeOps();
                while (opASTIterator.hasNext()){
                    PcodeOp pcodeOp = opASTIterator.next();
                    if (pcodeOp.getOpcode()==PcodeOp.CALL){
                        if (getFunctionName(pcodeOp.getInput(0).getAddress()).equals(targetFunction)){
                            //2.过滤常量参数  {要考虑bss段的情况，bss段使用p-code描述也是Unique类型}   增加判断不能Def的情况
                            if (pcodeOp.getInput(1).getDef()==null ||pcodeOp.getInput(1).getDef().getOpcode()!=PcodeOp.COPY){
                                //3.list表中过滤重复
                                if (!decompileResults.contains(results))
                                    decompileResults.add(results);
                            }

                        }
                    }
                }
            }
        }

        //3.调用栈与参数链跟踪处理
        if (!decompileResults.isEmpty())
            FirstFunction.addAll(decompileResults);
        else printerr(targetFunction+" 索引为null! ");

        return decompileResults;
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
        if (!arrayList.isEmpty())
            AllFunction.addAll(arrayList);
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
    private ArrayList<String> Pattterns(String compiles){
        if (compiles.equals("null")) return null;
        ArrayList<String> fomats = new ArrayList<>();
        Pattern pattern = Pattern.compile("(%(?: \\d+\\$)?(?: s|d|s|c))");
        Matcher matcher = pattern.matcher(compiles);
        while (matcher.find())
            fomats.add(matcher.group(0));
        return fomats;
    }

    private void Horizontal_line(int Count){
        for (int i = 0; i <Count; i++)
            printf("-");
        printf("\n");
    }

    private String getFunctionName(Address funAddress){
        return getFunctionAt(funAddress).getName();
    }

    interface Callback{
        void Control(ArrayList<DecompileResults> decompileResults);
    }

    private boolean CheckInput(){
        if (targetFunction!=null && ParamCount!=0 && ParamType!=0&& TargetParam!=0){
            if (TargetParam <= ParamCount)
                return true;
        }
        return false;
    }

    //******************************************************************************************************************
    // 变量
    //******************************************************************************************************************
    private static String targetFunction="vos_system";      //跟踪的参数名
    private static int ParamCount= 1;                    //参数个数
    private static int ParamType = 1;                   //参数类型
    private static int TargetParam=1;                   //跟踪参数
    private static String FORMAT="%s";                  //格式化字符串
    private  static DecompInterface decompInterfaces = null;
    private static ArrayList<Function> AllFunction = new ArrayList<>();             //所有target引用
    private static ArrayList<Function> secondFunction = new ArrayList<>();          // 2层过滤
    private static ArrayList<DecompileResults> FirstFunction = new ArrayList<>();   // 1层过滤
    private static ArrayList<String> filterlist = new ArrayList<>();
    private static ArrayList<String> listfun = new ArrayList<>();
    static {
        filterlist.add("main");
        filterlist.add("_start");
        listfun.add("snprintf_s");
        listfun.add("strncpy_s");
    }

}
