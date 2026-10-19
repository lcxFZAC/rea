//@category REA Verification

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;

/** Run the production seed script against a minimal 32-bit import. */
public final class ReaSeedRegressionProbe extends GhidraScript {
    @Override
    public void run() throws Exception {
        currentProgram.getMemory().createUninitializedBlock(
            ".bss", toAddr(0x1000), 0x20, false
        );
        // Reproduce a PE loader's entry-only function before disassembly.
        currentProgram.getFunctionManager().createFunction(
            "loader_placeholder", toAddr(1), new AddressSet(toAddr(1)), SourceType.DEFAULT
        );
        runScript("ReaGhidraApplySeeds.java", new String[] { getScriptArgs()[0] });
        JsonObject report = JsonParser.parseString(
            currentProgram.getOptions(Program.PROGRAM_INFO)
                .getString("REA analysis seeds", null)
        ).getAsJsonObject();
        require(report.get("entries").getAsInt() == 5, "all seeds accounted for");
        require(report.get("function_created").getAsInt() == 1,
            "out-of-range seed must not disturb descending function order");
        require(report.get("function_existing").getAsInt() == 1, "loader placeholder accounted for");
        require(report.get("function_failed").getAsInt() == 0, "no swallowed function entry");
        require(getFunctionAt(toAddr(0)).getName().equals("seed_low"), "lower function name");
        require(getFunctionAt(toAddr(1)).getName().equals("seed_high"), "higher function name");
        require(getFunctionAt(toAddr(1)).getBody().getNumAddresses() == 2,
            "existing entry-only body must include decoded NOP and RET");
        require(getInstructionAt(toAddr(2)) != null, "existing seed flow decoded");
        require(getFunctionAt(toAddr(0)).getBody().getNumAddresses() == 1,
            "lower body must not swallow existing higher entry");
        require(report.get("label_applied").getAsInt() == 1, "mapped BSS label applied");
        require(currentProgram.getSymbolTable().getPrimarySymbol(toAddr(0x1000))
            .getName().equals("seed_global"), "BSS label name");
        require(report.get("unmapped").getAsInt() == 2,
            "only out-of-range function and uninitialized code seed are skipped");
        require(report.get("code_decoded").getAsInt() == 0, "BSS is not decoded");
        runScript("ReaGhidraApplySeeds.java", new String[] { getScriptArgs()[0] });
        require(getFunctionAt(toAddr(1)).getBody().getNumAddresses() == 2,
            "repeat seed preserves established body");
        require(getFunctionAt(toAddr(0)).getBody().getNumAddresses() == 1,
            "repeat seed preserves a valid one-byte function body");
        require(getByte(toAddr(0)) == (byte)0x90 && getByte(toAddr(1)) == (byte)0x90 &&
            getByte(toAddr(2)) == (byte)0xc3, "source bytes unchanged");
        println("REA_SEED_REGRESSION_OK " + report);
    }

    private void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
