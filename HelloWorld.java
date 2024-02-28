//TODO write a description for this script
//@author 
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.ClangHighlightListener;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerManager;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.script.Ingredient;
import ghidra.app.plugin.core.script.IngredientDescription;
import ghidra.app.script.GatherParamPanel;
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
import ghidra.program.model.graph.*;

import java.awt.*;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HelloWorld extends GhidraScript implements Ingredient {

    private DecompInterface decompInterface=null;
    @Override
    public void run() throws Exception {

        /*
        IngredientDescription[] ingredients = getIngredientDescriptions();
        for (IngredientDescription ingredient : ingredients) {
            state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
                    ingredient.getDefaultValue());
        }
        if (!state.displayParameterGatherer("Script Options")) {
            return;
        }

        String OverlayName = (String) state.getEnvironmentVar("OverlayName");
        String OverlayHeaderName = (String) state.getEnvironmentVar("OverlayHeaderName");

        printf("%s %s \n",OverlayName,OverlayHeaderName);


         */


        Color SEARCH_HIGHLIGHT_DEF = new Color(100, 0, 255);
        decompInterface = getDecompInterface();
        FunctionIterator iterator2 =currentProgram.getListing().getFunctions(true);

        for (Function function : iterator2) {
            //printf("\t%s\n",function.getName());
            if (function.getName().equals("FUN_0041e9d0")){
                DecompileResults decompileResults = decompInterface.decompileFunction(function,0,getMonitor());
                Iterator<PcodeOpAST> iterator = decompileResults.getHighFunction().getPcodeOps();
                while (iterator.hasNext()){
                    PcodeOpAST pcodeOpAST = iterator.next();
                    //printf("%s\n",pcodeOpAST.toString());
                    if (pcodeOpAST.getOpcode()==PcodeOp.CALL){



                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("system")){
                            //if (pcodeOpAST.getInput(1).getDef().getOpcode()==PcodeOp.COPY) continue;
                            printf("\t system @ %s\n",pcodeOpAST.getInput(0).getPCAddress());

                            HighParam highParam = decompileResults.getHighFunction().getLocalSymbolMap().getParam(0);
                            printf("\n%s\n",highParam.getName());
                            printf("\n[pcode] %s\n",pcodeOpAST.getInput(1).getHigh().getName());

                            printf("\n[pcode] %s @ %s\n",pcodeOpAST.getInput(1).getDef().getInput(0).getDef(),pcodeOpAST.getInput(1).getDef().getInput(0).getPCAddress());
                            printf("system => %s\n\n",pcodeOpAST.toString());




                        }


                        /*
                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("asprintf")){
                            printf("%s\n",pcodeOpAST.getInput(1).getDef());
                            //printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(1).getOffset());
                            printf("asprintf => %s\n",pcodeOpAST.toString());
                        }

                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("system")){
                            if (pcodeOpAST.getInput(1).isConstant()){
                                printf("常量\n");
                                continue;
                            }
                            if (pcodeOpAST.getInput(1).getDef().getOpcode()==PcodeOp.COPY) continue;
                            //printf("%d\n",pcodeOpAST.getInput(1).getDef().getInput(0).getDef());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(0).getDef());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef());
                            printf("system  => %s\n",pcodeOpAST.toString());

                        }


                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("vsnprintf")){
                            printf("%s\n",pcodeOpAST.getInput(1).getDef());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(1).getOffset());
                            printf("vsnprintf => %s\n",pcodeOpAST.toString());
                        }

                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("snprintf")){
                            printf("%d\n",pcodeOpAST.getNumInputs());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(0).getAddress().toString());
                            //printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(1).getOffset());
                            printf("snprintf => %s\n",pcodeOpAST.toString());
                        }
                        if (getFunctionName(pcodeOpAST.getInput(0).getAddress()).equals("snprintf_s")){
                            printf("%d\n",pcodeOpAST.getNumInputs());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef());
                            printf("%s\n",pcodeOpAST.getInput(1).getDef().getInput(1).getOffset());
                            printf("snprintf => %s\n",pcodeOpAST.toString());
                        }


 */

                        //printf("\n");
                    }
                        //printf("\t\t%s\n",getFunctionName(pcodeOpAST.getInput(0).getAddress()));
                }
            }
        }










/*
        ArrayList<String> fomarts  = Pattterns("aaaa%dasssss%saaaaa");
        for (int i = 0; i < fomarts.size(); i++) {
            printf("%s\n",fomarts.get(i));
        }
         */
    }


    private ArrayList<String> Pattterns(String compiles){
        ArrayList<String> fomats = new ArrayList<>();
        Pattern pattern = Pattern.compile("(%(?: \\d+\\$)?(?: s|d|s|c))");
        Matcher matcher = pattern.matcher(compiles);
        while (matcher.find())
            fomats.add(matcher.group(0));
        return fomats;
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

    @Override
    public IngredientDescription[] getIngredientDescriptions() {
        IngredientDescription[] retVal = new IngredientDescription[] {
                new IngredientDescription("OverlayName", "Input Function Name ", GatherParamPanel.STRING, "system"),
                new IngredientDescription("OverlayHeaderName", "Input Param Count", GatherParamPanel.STRING, "false") };
        return retVal;
    }

    private String getFunctionName(Address funAddress){
        return getFunctionAt(funAddress).getName();
    }
}
