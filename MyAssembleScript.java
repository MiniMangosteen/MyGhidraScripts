//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
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

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;

public class MyAssembleScript extends GhidraScript {

    public void run() throws Exception {
//TODO Add User Code Here

        /*
        monitor.setMessage("Constructing Assember");
        // First, obtain an assembler bound to the current program.
        // If a suitable assembler has not yet been build, this will take some time to build it.
        Assembler asm = Assemblers.getAssembler(currentProgram);

        monitor.setMessage("Awaiting Input");
        // Put the current instruction text in by default.
        Instruction ins = getInstructionAt(currentAddress);
        String cur = "";
        if (ins != null) {
            cur = ins.toString();
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i <ins.getBytes().length ; i++) {
            builder.append(String.format("%x ",ins.getBytes()[i]));
        }
        println(ins.getAddress().toString());
        println(builder.toString());
        println(cur);


         */
        File f = new File("/Volumes/Mac/MyTools/ghidra_9.1.2_PUBLIC","mypcode.txt");
        PrintWriter pw = new PrintWriter(f);
        DecompileOptions options = new DecompileOptions();
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(options);
        ifc.setSimplificationStyle("decompile");

        Language language = currentProgram.getLanguage();
        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        Function function=null;
        FunctionManager functionManager = currentProgram.getFunctionManager();

        while(functions.hasNext()){
            function = functions.next();
            //println(function.getName());
            if (function.getName().equals("FUN_00180808")){

                DecompileResults res = ifc.decompileFunction(function,300,getMonitor());
                HighFunction highFunction = res.getHighFunction();




                Address add = function.getEntryPoint();     //函数指针
                Instruction points = getInstructionAt(add);
                AddressSetView v = function.getBody();
                println("函数结束地址："+v.getMaxAddress().toString());      //函数结束地址
                println("函数起始地址："+v.getMinAddress().toString());      //函数起始地址
                //println(points.toString());
                //println(getReferencesFrom(add).length+" ");

                while(v.getMaxAddress()!=points){
                    points = points.getNext();
                    if (points==null) break;
                    PcodeOp[] ops =  points.getPcode();
                    //println("address: "+points.getAddress().toString());

                    for (int i = 0; i < ops.length; i++) {
                        //pw.println(ops[i].toString());
                        //println(ops[i].getMnemonic());
                        Varnode vn = ops[i].getOutput();
                        //println(ops[i].getMnemonic(ops[i].getOpcode())+" "+ops[i].getOpcode());

                        if (vn!=null){

                            for (int j=0;j<ops[i].getNumInputs();j++){

                                pw.println(" "+vn.toString(language)+" "+ops[i].getMnemonic()+" "+ops[i].getInput(j).toString(language)+":"
                                +ops[i].getInput(j).getSize());





                            }

                        }
                    }
                }


            }

        }

        // Now present the prompt and assemble the given text.
        // The assembler will patch the result into the bound program.
       // asm.assemble(currentAddress, askString("Assemble", "Type an instruction", cur));
    }

}
