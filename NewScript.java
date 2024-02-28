/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Generate WARNING Bookmarks on instructions which have unimplemented pcode.
// Similar to disassembler's built-in marking but allows for refresh after 
// language update.
// @category sleigh
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.List;

public class NewScript extends GhidraScript {

	private String targetFunction = "";	//要反编译的函数
	@Override
	public void run() throws Exception {
		List<String> ls = new ArrayList<>();
		ls.add("1");
		ls.add("2");
		ls.add("3");
		ls.add("4");
		ls.add("5");
		ls.add("6");
		ls.add("77");
		ls.add("8");
		ls.add("9");
		String out = askChoice("List Function","text",ls,ls.get(0));
		println(out);


		DecompInterface decompInterface=getDecompInterface();
		FunctionIterator iterator =  currentProgram.getFunctionManager().getExternalFunctions();
		for (Function f : iterator) {
			if (f.getName().equals("vos_system")) {
				printf("%s %s\n",f.getName(),f.getEntryPoint().toString());
			}
		}

		printerr("-----");
		//这种方法可以很好的拿到封装函数的地址，另外两种方法只能拿到导出函数地址，无法拿到封装函数
		FunctionIterator iterator2 =currentProgram.getListing().getFunctions(true);
		for (Function ffs :
				iterator2) {
			if (ffs.getName().equals("vos_system"))
			{
				if (ffs.isThunk())
					printf("%s %s\n",ffs.getName(),ffs.getEntryPoint().toString());
			}
		}


		printerr("-----");

		FunctionManager manager = state.getCurrentProgram().getFunctionManager();
		FunctionIterator iterator1 =  manager.getExternalFunctions();
		for (Function fs : iterator1){
			if (fs.getName().equals("vos_system")){
				if (fs.isExternal())
					printf("%s %s\n",fs.getName(),fs.getEntryPoint().toString());
			}
		}

		printerr("-----");

		SymbolTable st = state.getCurrentProgram().getSymbolTable();
		SymbolIterator iter = st.getSymbolIterator(true);
		int count = 0;
		while (iter.hasNext() && !monitor.isCancelled()) {
			Symbol sym = iter.next();
			if (sym != null) {
				if (sym.getName().equals("vos_system"))
					if (sym.isDynamic())
						printf("%s %s\n",sym.getName(),sym.getAddress());
				count++;
			}
		}
		println(count+" symbols");

	}


	private void text() throws DecompileException {
		DecompInterface decompInterface=getDecompInterface();
		FunctionIterator iterator =  currentProgram.getFunctionManager().getExternalFunctions();
		for (Function f : iterator) {
			if (f.getName().equals(targetFunction)){
				DecompileResults results= decompInterface.decompileFunction(f,0,getMonitor());
				printf("%s",results.getDecompiledFunction().getC());
			}
		}
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

}
