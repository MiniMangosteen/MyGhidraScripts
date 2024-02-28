// 函数参数静态数据流跟踪
//@author hx
//@category 参数流跟踪第4版本
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Dataflow4 extends GhidraScript implements Ingredient {

    public void run() throws Exception {


        IngredientDescription[] ingredients = getIngredientDescriptions();
        for (IngredientDescription ingredient : ingredients) {
            state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
                    ingredient.getDefaultValue());
        }
        if (!state.displayParameterGatherer("Script Options")) {
            return;
        }

        String InputName = (String) state.getEnvironmentVar("Name");
        String IsDebugger = (String) state.getEnvironmentVar("Debugger");
        if (!InputName.isEmpty())
            targetFunction = InputName;

        if (!IsDebugger.isEmpty())
            OpenDebugger = Boolean.parseBoolean(IsDebugger);



        if (!CheckInput()){
            Horizontal_line(80);
            printerr("输入错误，脚本结束运行！");
            Horizontal_line(80);
            return;
        }

        Horizontal_line(80);
        printf(" \t\t %s \n",targetFunction);
        Horizontal_line(80);

        AllFunction.clear();

        decompInterfaces = getDecompInterface();
        SecondFilter(FirstFilter(FunctionReferences(targetFunction)), decompInterfaces-> {
            Horizontal_line(80);
            printf("\t全部引用\n");
            int i=0;
            for (; i < AllFunction.size(); i++) {
                printf("\t\t [%s] @ %s \n",AllFunction.get(i).getName(),AllFunction.get(i).getEntryPoint().toString());
            }
            printf("\t总计: %d\n",i);
            Horizontal_line(80);
        });

        printf("\n");

    }



    //******************************************************************************************************************
    // 指针类型参数过滤,需要分析参数的组合过程，判断组合过程是否是常量 system字符串过滤方法，                  【不通用】
    //******************************************************************************************************************
    private boolean P_codeFilter(DecompileResults decompileResults){
        if (OpenDebugger)
            printf(" [==>] %s @ %s\n\n",decompileResults.getDecompiledFunction().getSignature(),decompileResults.getHighFunction().getFunction().getEntryPoint().toString());
        int OldIndex=-1;
        ArrayList<PcodeBlockBasic> pcodeBlockBasics = decompileResults.getHighFunction().getBasicBlocks();
        for (PcodeBlockBasic pcodeBlockBasic :pcodeBlockBasics) {
            Iterator<PcodeOp>  iterator = pcodeBlockBasic.getIterator();
            while (iterator.hasNext()){
                PcodeOp op = iterator.next();
                if ((op.getOpcode()==PcodeOp.CALL) && getFunctionName(op.getInput(0).getAddress()).equals(targetFunction)){

                    if (op.getInput(1)==null)       //无参数情况
                        continue;

                    if (op.getInput(1).isConstant()){
                        printf("常量 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef()==null) {
                        printf("形参 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()==PcodeOp.LOAD){
                        printf("形参数组 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()==PcodeOp.PTRSUB || op.getInput(1).getDef().getOpcode()==PcodeOp.PTRADD){
                        ArrayList<PcodeOp> pcodeOpArrayList = FindRegs(pcodeBlockBasics,pcodeBlockBasic.getIndex(),1,op);
                        if (!pcodeOpArrayList.isEmpty()){
                            if (!Options(pcodeOpArrayList))
                                return false;
                        }
                        printf("数组 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()==PcodeOp.CAST){

                        ArrayList<PcodeOp> pcodeOpArrayList = FindRegs(pcodeBlockBasics,pcodeBlockBasic.getIndex(),2,op);
                        if (!pcodeOpArrayList.isEmpty()){
                            if (!Options(pcodeOpArrayList))
                                return false;
                        }
                        printf("指针 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()== PcodeOp.MULTIEQUAL || op.getInput(1).getDef().getOpcode()==PcodeOp.INDIRECT){
                        printf("数组M @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()==PcodeOp.CALL){
                        printf("堆栈 @ %s\n",op.getInput(0).getPCAddress());
                        return true;
                    }

                    if (op.getInput(1).getDef().getOpcode()==PcodeOp.COPY)
                        continue;

                    printf("\t%s %s\n",decompileResults.getHighFunction().getFunction().getName(), op.getInput(1).getDef());

                }
            }
            OldIndex = pcodeBlockBasic.getIndex();
        }
        return false;
    }


    //******************************************************************************************************************
    // 为了证明组合参数是否可控
    //******************************************************************************************************************
    private boolean Options(ArrayList<PcodeOp> pcodeOps){
        int count=0;
        for (PcodeOp p : pcodeOps) {
            //printf("\t%s\n",getFunctionName(p.getInput(0).getAddress()));
            switch (getFunctionName(p.getInput(0).getAddress())){
                case "sprintf":
                    if(CheckSprintf(p))
                        count++;
                    break;
                case "snprintf_s":
                    if(CheckSnprintf_s(p))
                        count++;
                    break;
                case "snprintf":
                    if(CheckSnprintf(p))
                        count++;
                    break;
                case "vsnprintf":
                    if(CheckVsnprintf(p))
                        count++;
                    break;
                case "asprintf":
                    if (CheckAsprintf(p))
                        count++;
                    break;
            }
        }
        if (0 != count) {
            return true;
        } else
            return false;
    }


    private boolean CheckSnprintf(PcodeOp op){

        return CheckParams(op,3);
    }

    private boolean CheckSprintf(PcodeOp op){

        return CheckParams(op,2);
    }

    private boolean CheckVsnprintf(PcodeOp op){

        return true;
    }

    private boolean CheckSnprintf_s(PcodeOp op){

        return CheckParams(op,4);
    }

    private boolean CheckAsprintf(PcodeOp op){

        return CheckParams(op,2);
    }

    private boolean CheckParams(PcodeOp op,int index){

        try {
            int count=0;
            //printf("%s\n",getDataAt(toAddr(op.getInput(index).getDef().getInput(0).getOffset())));
            ArrayList<String> stringArrayList = Pattterns(getDataAt(toAddr(op.getInput(index).getDef().getInput(0).getOffset())).toString());
            assert stringArrayList != null;
            if (!stringArrayList.isEmpty()){
                for (int i = 0; i < stringArrayList.size(); i++) {
                    switch (stringArrayList.get(i)){
                        case "%s":
                            if(CheckUnique(op,index+1+i))
                                count++;
                            break;
                        case "%d":
                            break;
                        default:
                            break;
                    }
                }
            }else{

                return false;
            }
            if (count==0)
                return false;
        }catch (Exception e){
            printf("\t[-] %s\n",e.toString());
        }

        return true;
    }

    private boolean CheckUnique(PcodeOp op,int index) throws Exception {
            if (op.getInput(index).isUnique())
                if (op.getInput(index).getDef().getOpcode()==PcodeOp.COPY)
                    return false;

            return true;
    }

    //******************************************************************************************************************
    // 数组处理
    //******************************************************************************************************************
    private ArrayList<PcodeOp> FindRegs(ArrayList<PcodeBlockBasic> pcodeBlockBasics, int Index, int OldIndex, PcodeOp op){
        ArrayList<PcodeOp> pcodeopArrayList = new ArrayList<PcodeOp>();
        for (int i = Index; i > -1 ; i--) {
            Iterator<PcodeOp> opIterator = pcodeBlockBasics.get(i).getIterator();
            while (opIterator.hasNext()){
                PcodeOp oop = opIterator.next();
                if (oop.getOpcode()==PcodeOp.CALL){
                    if (!getFunctionName(oop.getInput(0).getAddress()).equals(targetFunction) && oop.getNumInputs()>4 ){
                        if (FilterType(oop,OldIndex,op))
                            pcodeopArrayList.add(oop);
                    }
                }
            }
        }
        return pcodeopArrayList;
    }




    private boolean FilterType(PcodeOp oop,int paramType,PcodeOp op){

        switch (paramType){
            case 1:
                if (oop.getInput(1).getDef()!=null &&
                        (oop.getInput(1).getDef().getOpcode()==PcodeOp.PTRSUB ||
                                oop.getInput(1).getDef().getOpcode() == PcodeOp.PTRADD)){
                    if (!(oop.getInput(1).getDef().getInput(1).getOffset() == op.getInput(1).getDef().getInput(1).getOffset()))
                        return false;
                }

            case 2:
                if (oop.getInput(1).getDef()!=null &&
                        oop.getInput(1).getDef().getOpcode()==PcodeOp.CAST){
                    if (!(oop.getInput(1).getDef().getInput(0).getAddress().equals(op.getInput(1).getDef().getInput(0).getAddress())))
                        return false;
                }

        }
        return true;
    }




    //******************************************************************************************************************
    // 二次过滤函数内target组合参数情况                                                                  【定制不通用】
    //******************************************************************************************************************
    private void SecondFilter(ArrayList<DecompileResults> decompileResultsArrayList, Callback callback){
        int count=0;
        for (DecompileResults d : decompileResultsArrayList) {
            if (P_codeFilter(d)){
                count++;
                printf(" [=======>] %s @ %s\n\n",d.getDecompiledFunction().getSignature(),d.getHighFunction().getFunction().getEntryPoint().toString());
            }
        }
        printf("\t 总计：%d\n",count);
        callback.Control(decompileResultsArrayList);
    }


    //******************************************************************************************************************
    //Get DecompileResults
    //******************************************************************************************************************
    private ArrayList<DecompileResults> FirstFilter(ArrayList<Function> refxlist){
        ArrayList<DecompileResults> decompileResults = new ArrayList<>();
        for (Function f : refxlist) {
            DecompileResults results = decompInterfaces.decompileFunction(f, 0, getMonitor());
            Iterator<PcodeOpAST> opASTIterator = results.getHighFunction().getPcodeOps();
            while (opASTIterator.hasNext()){
                PcodeOp pcodeOp = opASTIterator.next();
                if (pcodeOp.getOpcode()==PcodeOp.CALL){
                    if (getFunctionName(pcodeOp.getInput(0).getAddress()).equals(targetFunction)){
                        if (!decompileResults.contains(results))
                            decompileResults.add(results);
                    }
                }
            }
        }
        return decompileResults;
    }

    //******************************************************************************************************************
    // 查找 targetName 的交叉引用                                                                       【通用型过滤】
    //******************************************************************************************************************
    private ArrayList<Function> FunctionReferences(String targetName){
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

    @Override
    public IngredientDescription[] getIngredientDescriptions() {
        IngredientDescription[] retVal = new IngredientDescription[] {
                new IngredientDescription("Name", "Input Target Function  Name", GatherParamPanel.STRING, "system"),
                new IngredientDescription("Debugger", "Is off/on Debugger", GatherParamPanel.STRING, "false") };
        return retVal;
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
    private static String targetFunction;               //跟踪的参数名
    private static int ParamCount= 1;                    //参数个数
    private static int ParamType = 1;                   //参数类型
    private static int TargetParam=1;                   //跟踪参数
    private static String FORMAT="%s";                  //格式化字符串
    private static boolean OpenDebugger=false;            //开启调试
    private  static DecompInterface decompInterfaces = null;
    private static ArrayList<Function> AllFunction = new ArrayList<>();             //所有target引用
    private static ArrayList<String> filterlist = new ArrayList<>();
    private static ArrayList<String> listfun = new ArrayList<>();
    static {
        targetFunction=null;
        AllFunction.clear();
        filterlist.add("main");
        filterlist.add("_start");
        listfun.add("snprintf_s");
        listfun.add("strncpy_s");
    }
}
