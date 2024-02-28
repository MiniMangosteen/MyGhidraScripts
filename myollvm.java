import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.util.bin.format.pe.ControlFlowGuard;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.pcodeCPort.slghpattern.Pattern;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.pcode.*;

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;

/*
 学习反混淆的脚本
 1.打印输出pcode 中间代码
 2.打印输出Block快地址
 3.循环匹配目标pcode指令
 4.path块中的代码修改汇编
 */
public class myollvm extends HeadlessScript {
    @Override
    protected void run() throws Exception {
        //File f = new File("/Volumes/Mac/MyTools/ghidra_9.1.2_PUBLIC","log.txt");
        //PrintWriter pw = new PrintWriter(f);

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
        FunctionIterator fi = listing.getFunctions(true);
        Function function;


        //汇编代码操作对象
        Assembler asm =  Assemblers.getAssembler(currentProgram);   //获取与程序关联的汇编器对象
        //byte[] bytes = asm.assembleLine(currentAddress,"JMP  0x100000ca8");
        //asm.assemble(currentAddress,"JMP   0x100000ca8");
        //byte[] b = getBytes(currentAddress,4);
        //println(String.format("0x%x 0x%x  0x%x  0x%x",b[0],b[1],b[2],b[3]));





        String static_val=null;
        while(fi.hasNext()){
            function = fi.next();
            if (function.getName().equals("_target_function")){
                DecompileResults decompileResults = ifc.decompileFunction(function,60,monitor);
                HighFunction highFunction = decompileResults.getHighFunction();
                //函数中pcode抽象语法
                Iterator<PcodeOpAST> opASTIterator = highFunction.getPcodeOps();
                for (;opASTIterator.hasNext();){
                    PcodeOpAST pcodeOpAST = opASTIterator.next();
                    //pw.println(pcodeOpAST.toString());
                    if (pcodeOpAST.getOpcode()== PcodeOp.COPY){
                        println("[+] static val is "+pcodeOpAST.getInput(0).toString(language));
                        static_val = pcodeOpAST.getInput(0).toString(language);

                        break;
                    }
                }
                if (static_val!=null)println("[+] static val is "+static_val);
                println("------------------------------------------------------");
                //代码基本块
                PcodeOp tmp=null;
                ArrayList<PcodeBlockBasic> list = highFunction.getBasicBlocks();
                for (PcodeBlockBasic p : list) {
                    println(p.toString()+" size is "+p.getOutSize());
                    //p.getOutSize() 输出1和2。推测为块跳转输出的路径。1代表只有一种执行路径。2代表有判断跳转两种执行路径。
                    if (p.toString().equals("basic@100000ca8")){
                        //指定地址内写入汇编，两种写法，修改关联后cfg图需要刷新才能更改
                        //1.第一种写法，目标地址上汇编返回byte数组，使用patchProgram函数更新Listing的汇编代码
                        //byte[] ret =  asm.assembleLine(p.getStart(),"MOV    ECX,0x93e43df7");
                       // asm.patchProgram(ret , p.getStart());
                        //2.第二中写，目标地址上立即汇编并关联listing
                        //asm.assemble(p.getStart(),"JMP      0x100000ca8");
                        println(String.format("max %s , min %s",p.getStop().toString(),p.getStart().toString()));

                    }

                    if (p.getOutSize()!=2)
                        continue;

                    //块中的pcode
                    Iterator<PcodeOp>  pcodeOpIterator =  p.getIterator();
                    while(pcodeOpIterator.hasNext()){
                       tmp = pcodeOpIterator.next();
                       //println("[+] iterator pcode "+tmp.toString());
                    }

                    if (tmp==null)
                        continue;

                    //不是条件跳转
                    if (tmp.getOpcode()!=PcodeOp.CBRANCH)
                        continue;

                    Varnode condition = tmp.getInput(1);
                    PcodeOp condition_pcode = condition.getDef();
                    //println("[+] condition pcode "+condition_pcode.toString());

                    if (condition_pcode.getOpcode()==PcodeOp.INT_NOTEQUAL||
                    condition_pcode.getOpcode()==PcodeOp.INT_EQUAL){

                        Varnode var1= condition_pcode.getInput(0);
                        Varnode var2= condition_pcode.getInput(1);
                    }
                }
            }//end method
        }
        //pw.close();
    }
}
