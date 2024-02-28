# Ghidra 脚本开发

> 编写各种功能的脚本并使用和记录

- vos_system.java system函数参数的脚本跟踪
- NewScript.java 简单的目标函数反编译为伪C代码
- MyPcode.java Demo学习Pcode中间的API的调用
- HighFunction2LLVM 该脚本是网上MIT开源的，将Pcode转换为ir中间码并重编译为可执行文件
- pcode_inspector.py 指令解析执行引擎



简单介绍：https://bbs.kanxue.com/thread-262373.htm



效果图：

![gs1](./images/gs1.png)

![gs2](./images/gs2.png)



![gs3](./images/gs3.png)



![gs4](./images/gs4.png)





![gs5](./images/gs5.png)








# 学习记录
- currentProgram：活动程序
- currentAddress：工具中当前光标位置的地址
- currentLocation：工具中当前光标位置的程序位置；如果不存在程序位置，则为null
- currentSelection：工具中的当前选择；如果不存在选择，则为null
- currentHighlight：工具中的当前突出显示；如果不存在突出显示，则为null
- printerr() 函数在控制台打印信息，字体标注为醒目红色

- FunctionIterator iterator = currentProgram.getListing().getFunctions(true) //获取当前项目中函数迭代器

- Reference[] references = getReferencesTo(Function.getEntryPoint()) //获取当前函数所有交叉引用

- Function func = getFunctionContaining(Address) //根据address返回函数对象


``` Java
下拉框实现函数
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
		println(out);   //输出选中的项
```
``` Java
项目所有符号表
        SymbolTable st = state.getCurrentProgram().getSymbolTable();
        SymbolIterator iter = st.getSymbolIterator(true);
        int count = 0;
        while (iter.hasNext() && !monitor.isCancelled()) {
            Symbol sym = iter.next();
            if (sym != null) {
                println(sym.getName());
                count++;
            }
        }
        println(count+" symbols");
```

``` Java
函数形参
     DecompileResults results =  decompInterface.decompileFunction(function,0,getMonitor()); //function为目标函数
     printf("\t %s\n", results.getDecompiledFunction().getSignature());      //函数签名
     printf("\t %d\n", results.getHighFunction().getLocalSymbolMap().getNumParams()); //函数参数个数
     printf("\t %s\n", results.getHighFunction().getLocalSymbolMap().getParam(0).getDataType().getDisplayName()); //函数参数的类型
     printf("\t %d\n", results.getHighFunction().getNumVarnodes());          //函数varnodes个数
```

``` Java
交叉引用固定写法代码如下
    DecompInterface decompInterface=getDecompInterface();
    ArrayList<Function> functionArrayList = findCallFunctions("open");        //寻找open函数的所有交叉引用
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
```

``` Java
传入地址返回函数名

    private String getFunctionName(Address funAddress ) {

            return getFunctionAt(funAddress).getName();

     }

```

``` Java
反编译c代码
    DecompileResults results = decompInterface.decompileFunction(f, 0, getMonitor());
    results.getDecompiledFunction().getC();     //返回c代码字符串
    results.getCCodeMarkup().toString();      //使用token方法返回c代码字符串
    ClangTokenGroup clangTokenGroup = results.getCCodeMarkup();     //行打印
    for (int i = 0; i < clangTokenGroup.numChildren(); i++) {
          printf("%s\n",clangTokenGroup.Child(i));
     }
    //标准打印方式，按照反编译窗口内容的方式打印输出
    ArrayList<ClangLine> clangLineArrayList =  DecompilerUtils.toLines(results.getCCodeMarkup());
    for (ClangLine c : clangLineArrayList) {
           printf("\t%s\n\n", c.toString());
    }
```

``` Java
三种适合获取所有Function对象的方法
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


```


``` Java
增加界面
要实现Ingredient接口
public class HelloWorld extends GhidraScript implements Ingredient{
     @Override
    public void run() throws Exception {
        //将创建的id添加到面板上
         IngredientDescription[] ingredients = getIngredientDescriptions();
          for (IngredientDescription ingredient : ingredients) {
                state.addParameter(ingredient.getID(), ingredient.getLabel(), ingredient.getType(),
                      ingredient.getDefaultValue());
          }
           //这里是添加标题
          if (!state.displayParameterGatherer("Script Options")) {
                  return;
           }

        //这里是根据ID返回输入的内容
        String OverlayName = (String) state.getEnvironmentVar("OverlayName");
        String OverlayHeaderName = (String) state.getEnvironmentVar("OverlayHeaderName");
        //打印输入的内容
        printf("%s %s \n",OverlayName,OverlayHeaderName);
    }

   @Override
   public IngredientDescription[] getIngredientDescriptions() {
          IngredientDescription[] retVal = new IngredientDescription[] {
                  new IngredientDescription("OverlayName", "函数名", GatherParamPanel.STRING, "1111"),
                  new IngredientDescription("OverlayHeaderName", "第几个参数",
                          GatherParamPanel.STRING, "222") };
          return retVal;
      }
}
```

``` Java
增加字符获取
getDataAt(toAddr(offset));


```

``` Java
                //targetFunction getDef == null 为形参
                    //               getDef == COPY 为字符串常量
                    //               getDef == PTRSUB 数组
                    //               getDef == CAST 指针
                    //               getDef == MULTIEQUAL 数组 system(local_258[0]);

                    这种类型的指针向上索引可以找到赋值
                    (unique, 0x640, 8) PTRSUB (register, 0x20, 8) , (const, 0xfffffffffffffbe0, 8)
                    (stack, 0xfffffffffffffbe0, 8) COPY (const, 0x206d722f6e69622f, 8)
                    (stack, 0xfffffffffffffbe8, 8) COPY (const, 0x6d796d2f706d742f, 8)
                    (stack, 0xfffffffffffffc20, 1) COPY (const, 0x0, 1)
                    (stack, 0xfffffffffffffbf0, 8) COPY (const, 0x6d63626461696465, 8)
                    (stack, 0xfffffffffffffbf8, 8) COPY (const, 0x6b63616262642e64, 8)
                    (stack, 0xfffffffffffffc00, 8) COPY (const, 0x72676f72705f7075, 8)
                    (stack, 0xfffffffffffffc08, 8) COPY (const, 0x20676f6c2e737365, 8)
                    (stack, 0xfffffffffffffc10, 8) COPY (const, 0x6e2f7665642f203e, 8)
                    (stack, 0xfffffffffffffc18, 8) COPY (const, 0x31263e32206c6c75, 8)
                     ---  CALL (ram, 0x40cce0, 8) , (unique, 0x100003d5, 8)
                    (unique, 0x640, 8) PTRSUB (register, 0x20, 8) , (const, 0xfffffffffffffbe0, 8)
                    (unique, 0x100003d5, 8) CAST (unique, 0x640, 8)
                    system  =>  ---  CALL (ram, 0x40cce0, 8) , (unique, 0x100003d5, 8)

                      local_420[0] = 0x206d722f6e69622f;
                      local_420[1] = 0x6d796d2f706d742f;
                      local_3e0 = 0;
                      local_420[2] = 0x6d63626461696465;
                      local_420[3] = 0x6b63616262642e64;
                      local_400 = 0x72676f72705f7075;
                      local_3f8 = 0x20676f6c2e737365;
                      local_3f0 = 0x6e2f7665642f203e;
                      local_3e8 = 0x31263e32206c6c75;
                      system((char *)local_420);

                    这种类型指针可以索引出是组合偏移
                    (unique, 0x100006ed, 8) INT_ADD (register, 0x38, 8) , (const, 0xb48, 8)
                    (unique, 0x640, 8) CAST (unique, 0x100006ed, 8)
                    system  =>  ---  CALL (ram, 0x40cce0, 8) , (unique, 0x640, 8)

                    system((char *)(param_1 + 0xb48));


```

``` Java
点控制台窗口跳转到伪C行
                            Set<Varnode>  varnodeSet =  DecompilerUtils.getBackwardSlice(pcodeOpAST.getInput(1));
                            for (Varnode v : varnodeSet) {
                                goTo(v.getPCAddress());     //可以发消息跳转
                                printf("\t%s\n",v.getPCAddress());  //输出地址到控制台上，点击也可跳转到
                            }


```