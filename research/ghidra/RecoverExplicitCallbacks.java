// Recover explicitly reviewed atexit targets when Ghidra emitted no reference.
// @category GuliKit.Audit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.io.*;

public class RecoverExplicitCallbacks extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<2)throw new IllegalArgumentException("RecoverExplicitCallbacks.java OUTPUT_DIRECTORY HEX_ADDRESS...");
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        DecompInterface d=new DecompInterface();d.toggleCCode(true);d.openProgram(currentProgram);
        try(BufferedWriter w=Files.newBufferedWriter(out.resolve("recovery.tsv"));BufferedWriter refs=Files.newBufferedWriter(out.resolve("references.tsv"))) {
            w.write("address\tdisassembled\tfunction_found\tdecompiled\terror\n");
            for(int i=1;i<args.length;i++) {
                Address a=toAddr(Long.parseUnsignedLong(args[i].replace("0x",""),16));
                boolean decoded=disassemble(a);Function f=getFunctionAt(a);if(f==null&&decoded)f=createFunction(a,null);
                DecompileResults r=f==null?null:d.decompileFunction(f,10,monitor);
                boolean ok=r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null;
                if(ok)Files.writeString(out.resolve(a+".c"),"/* Explicit atexit callback "+a+" */\n"+r.getDecompiledFunction().getC(),StandardCharsets.UTF_8);
                w.write(a+"\t"+decoded+"\t"+(f!=null)+"\t"+ok+"\t"+(r==null?"no-function":r.getErrorMessage().replace('\n',' '))+"\n");w.flush();
                if(f!=null){InstructionIterator it=currentProgram.getListing().getInstructions(f.getBody(),true);while(it.hasNext()){Instruction ins=it.next();for(Reference ref:ins.getReferencesFrom())refs.write(a+"\t"+ins.getAddress()+"\t"+ins+"\t"+ref.getReferenceType()+"\t"+ref.getToAddress()+"\n");}}
            }
        }finally{d.dispose();}
    }
}
