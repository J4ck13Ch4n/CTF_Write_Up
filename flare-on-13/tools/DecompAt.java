import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
public class DecompAt extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        String out = args[0];
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        for (int i = 1; i < args.length; i++) {
            Address a = currentProgram.getAddressFactory().getAddress(args[i]);
            Function f = getFunctionContaining(a);
            if (f == null) { pw.println("// no function at " + args[i]); continue; }
            DecompileResults r = d.decompileFunction(f, 120, monitor);
            pw.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + " (query " + args[i] + ")");
            if (r != null && r.decompileCompleted()) pw.println(r.getDecompiledFunction().getC());
            else pw.println("// decompile failed");
            pw.flush();
        }
        pw.close();
    }
}
