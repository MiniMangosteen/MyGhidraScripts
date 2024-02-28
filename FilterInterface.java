import ghidra.program.model.listing.Function;

public interface FilterInterface {
    boolean isConst(Function function);
    boolean isNotPar(Function function);


}
