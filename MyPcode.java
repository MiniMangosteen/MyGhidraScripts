import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.GraphService;
import ghidra.app.util.AddressInput;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcodeCPort.slghsymbol.Constructor;
import ghidra.program.database.references.ReferenceDBManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockModel;
import ghidra.program.model.lang.Language;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.ColorUtils;
import ghidra.util.Msg;
import ghidra.util.graph.DirectedGraph;
import ghidra.util.graph.SimpleWeightedDigraph;
import ghidra.util.table.ReferencesFromTableModel;

import java.util.ArrayList;
import java.util.Iterator;

public class MyPcode extends HeadlessScript {

    /*
    1.选择目标函数
    2.cfg输出所有调用栈
     */
    @Override
    protected void run() throws Exception {

        DecompileOptions options = new DecompileOptions();
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.setOptions(options);
        decompInterface.setSimplificationStyle("decompile");
        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        if (!decompInterface.openProgram(this.currentProgram)) {
            throw new DecompileException("Decompiler", "Unable to initialize: "+decompInterface.getLastMessage());
        }

        DecompileResults res = decompInterface.decompileFunction(getFunctionContaining(currentAddress),60,getMonitor());
        HighFunction highFunction = res.getHighFunction();
        highFunction.getBasicBlocks();
        Function fun;
        while (functions.hasNext()){
            fun = functions.next();
            //打印所有导出函数
           // println(fun.getName());
            if (fun.getName().equals("JNI_OnLoad")){




                Address point = fun.getEntryPoint();
                AddressSetView setView = fun.getBody();
                println("end:   "+setView.getMaxAddress().toString());    //函数结束地址
                println("start: "+setView.getMinAddress().toString());    //函数起始地址
                //println("----"+point.toString());
                Instruction instruction = getInstructionAfter(point);
                setView.getMinAddress().next();
                Reference[] references = getReferencesTo(currentAddress);
                for (int i = 0; i < references.length; i++) {
                    println(" "+references[i].getFromAddress() );   //拿到分发器的交叉引用

                }

                GraphService service =  state.getTool().getService(GraphService.class);
                if (service==null) println("GraphService is null!");
                else service.getGraphDisplay();

                //println(SymbolUtilities.getDynamicName(currentProgram, currentAddress));


                /*
                currentProgram：活动程序

                currentAddress：工具中当前光标位置的地址

                currentLocation：工具中当前光标位置的程序位置；如果不存在程序位置，则为null

                currentSelection：工具中的当前选择；如果不存在选择，则为null

                currentHighlight：工具中的当前突出显示；如果不存在突出显示，则为null
                 */
            }
        }



    }
}
