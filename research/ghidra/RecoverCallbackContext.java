// Enumerate data-to-code pointers and recover overlooked callback functions.
// Analysis metadata only: does not modify executable bytes or use device APIs.
// @category GuliKit.Audit
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.io.*;

public class RecoverCallbackContext extends GhidraScript {
    private String q(Object x) {
        if(x==null)return "null";
        return "\""+x.toString().replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t")+"\"";
    }
    private String obj(Object... p) {
        StringBuilder s=new StringBuilder("{");
        for(int i=0;i<p.length;i+=2){if(i>0)s.append(',');s.append(q(p[i])).append(':').append(q(p[i+1]));}
        return s.append('}').toString();
    }
    private long uint(Address a) throws Exception {return Integer.toUnsignedLong(currentProgram.getMemory().getInt(a));}
    private Set<Address> functions() {
        Set<Address> s=new TreeSet<>();FunctionIterator i=currentProgram.getFunctionManager().getFunctions(true);
        while(i.hasNext())s.add(i.next().getEntryPoint());return s;
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<1)throw new IllegalArgumentException("RecoverCallbackContext.java OUTPUT_DIRECTORY");
        Path out=Paths.get(args[0]);Files.createDirectories(out);Files.createDirectories(out.resolve("decompiled"));
        Memory mem=currentProgram.getMemory();Listing listing=currentProgram.getListing();FunctionManager fm=currentProgram.getFunctionManager();
        Set<Address> before=functions();Map<Address,Set<String>> recover=new TreeMap<>();TreeMap<Address,String> symbols=new TreeMap<>();
        SymbolIterator syms=currentProgram.getSymbolTable().getAllSymbols(true);
        while(syms.hasNext()){Symbol s=syms.next();if(s.getAddress().isMemoryAddress())symbols.put(s.getAddress(),s.getName(true));}
        long pointerCount=0,mapCount=0;
        try(BufferedWriter w=Files.newBufferedWriter(out.resolve("data-code-pointers.jsonl"));BufferedWriter maps=Files.newBufferedWriter(out.resolve("mfc-message-map-entries.jsonl"))) {
            for(MemoryBlock b:mem.getBlocks()) {
                // Scan every initialized readable non-executable memory block;
                // embedded data/resource coincidences are retained as candidates.
                if(!b.isInitialized() || !b.isRead() || b.isExecute())continue;
                long start=b.getStart().getOffset(),end=b.getEnd().getOffset();
                for(long pos=(start+3)&~3L;pos+3<=end && !monitor.isCancelled();pos+=4) {
                    Address source=toAddr(pos);Address target=toAddr(uint(source));MemoryBlock tb=mem.getBlock(target);
                    if(tb==null || !tb.isExecute())continue;pointerCount++;
                    Function containing=fm.getFunctionContaining(target);Instruction ins=listing.getInstructionAt(target);
                    Map.Entry<Address,String> near=symbols.floorEntry(source);String nearName=near==null?null:near.getValue();
                    long distance=near==null?Long.MAX_VALUE:source.subtract(near.getKey());
                    boolean vtable=nearName!=null && nearName.toLowerCase().contains("vftable") && distance<4096;
                    boolean init=nearName!=null && distance<4096 && (nearName.contains("__xc_") || nearName.contains("__xi_") || nearName.toLowerCase().contains("initializer"));
                    // Exact ranges independently recovered from __cinit at
                    // EXE 005027f8 and DLL __CRT_INIT at 10001566. Generic DAT
                    // labels hide these arrays from symbol-name heuristics.
                    boolean knownInit=(currentProgram.getImageBase().getOffset()==0x400000L &&
                        ((pos>=0x527958L && pos<0x527ce0L) || (pos>=0x527ce4L && pos<0x527d04L))) ||
                        (currentProgram.getImageBase().getOffset()==0x10000000L &&
                        ((pos>=0x100020a4L && pos<0x100020a8L) || (pos>=0x100020acL && pos<0x100020b4L)));
                    init=init || knownInit;
                    boolean mfc=false;
                    if(pos>=start+20) {
                        long msg=uint(source.subtract(20)),code=uint(source.subtract(16)),first=uint(source.subtract(12)),last=uint(source.subtract(8)),sig=uint(source.subtract(4));
                        // AFX_MSGMAP_ENTRY heuristic: message + code + ID range +
                        // member-function signature + code pointer. Preserve all
                        // fields for manual confirmation; this is not a type proof.
                        mfc=msg>0 && msg<=0x10000 && sig>0 && sig<=0x80 && first<=last && last<=0xffff && (code<=0xffff || code>=0xffff0000L);
                        if(mfc){mapCount++;maps.write(obj("entry",source.subtract(20),"message",String.format("0x%x",msg),"notification_code",String.format("0x%x",code),"first_id",first,"last_id",last,"signature",sig,"callback",target,"nearest_symbol",nearName,"confidence","heuristic; inspect neighboring entries/terminator"));maps.newLine();}
                    }
                    w.write(obj("source",source,"source_block",b.getName(),"target",target,"function",containing==null?null:containing.getName(true),"function_entry",containing==null?null:containing.getEntryPoint(),"defined_instruction",ins!=null,"nearest_symbol",nearName,"symbol_distance",distance,"possible_vtable",vtable,"possible_initializer",init,"possible_mfc_entry",mfc));w.newLine();
                    // Only well-anchored pointer contexts are promoted. Generic
                    // resource/data coincidences remain unresolved inventory rows.
                    if(containing==null && !b.getName().toLowerCase().contains("rsrc") && (vtable || init || mfc)) {
                        int first=Byte.toUnsignedInt(mem.getByte(target));
                        if(first!=0 && first!=0xcc)recover.computeIfAbsent(target,k->new TreeSet<>()).add("source="+source+";vtable="+vtable+";init="+init+";mfc="+mfc);
                    }
                }
            }
        }
        try(BufferedWriter w=Files.newBufferedWriter(out.resolve("recovery-attempts.jsonl"))) {
            for(Map.Entry<Address,Set<String>> e:recover.entrySet()) {
                if(monitor.isCancelled())break;
                Address a=e.getKey();boolean decoded=disassemble(a);Function f=fm.getFunctionAt(a);
                if(f==null && decoded)f=createFunction(a,null);
                w.write(obj("target",a,"reasons",e.getValue(),"disassembled",decoded,"created_or_found",f!=null,"function",f==null?null:f.getName(true)));w.newLine();
            }
        }
        // Newly recovered initializers often register exit callbacks by PUSHing
        // an immediate code pointer; those pointers are in .text, not a data
        // array. Follow direct calls and code-pointer references from the new
        // functions for at most three rounds, with a hard 1000-function cap.
        // Keep every attempted edge so heuristic promotions remain reviewable.
        Set<Address> closureScanned=new HashSet<>();
        long closureAttempts=0;
        try(BufferedWriter w=Files.newBufferedWriter(out.resolve("initializer-callback-closure.jsonl"))) {
            for(int round=0;round<3 && !monitor.isCancelled();round++) {
                Set<Address> frontier=functions();frontier.removeAll(before);frontier.removeAll(closureScanned);
                if(frontier.isEmpty())break;
                Map<Address,String> targets=new TreeMap<>();
                for(Address entry:frontier) {
                    closureScanned.add(entry);Function f=fm.getFunctionAt(entry);
                    InstructionIterator it=listing.getInstructions(f.getBody(),true);
                    while(it.hasNext()) {
                        Instruction ins=it.next();
                        for(Reference ref:ins.getReferencesFrom()) {
                            Address target=ref.getToAddress();MemoryBlock block=mem.getBlock(target);
                            boolean call=ref.getReferenceType().isCall();
                            boolean pointer=ref.getReferenceType().isData() &&
                                (ins.getMnemonicString().equalsIgnoreCase("PUSH") || ins.getMnemonicString().equalsIgnoreCase("MOV"));
                            if(block==null || !block.isExecute() || (!call && !pointer) || fm.getFunctionContaining(target)!=null)continue;
                            int first=Byte.toUnsignedInt(mem.getByte(target));if(first==0 || first==0xcc)continue;
                            targets.put(target,"from="+ins.getAddress()+";owner="+entry+";type="+ref.getReferenceType());
                        }
                    }
                }
                for(Map.Entry<Address,String> e:targets.entrySet()) {
                    if(monitor.isCancelled() || functions().size()-before.size()>=1000)break;
                    closureAttempts++;Address a=e.getKey();boolean decoded=disassemble(a);Function f=fm.getFunctionAt(a);
                    if(f==null && decoded)f=createFunction(a,null);
                    w.write(obj("round",round,"target",a,"edge",e.getValue(),"disassembled",decoded,"created_or_found",f!=null,"confidence","static immediate-code-pointer/direct-call edge; callback role requires review"));w.newLine();
                }
            }
        }
        Set<Address> after=functions();Set<Address> added=new TreeSet<>(after);added.removeAll(before);
        DecompInterface d=new DecompInterface();d.toggleCCode(true);d.openProgram(currentProgram);
        long ok=0,failed=0;
        try(BufferedWriter index=Files.newBufferedWriter(out.resolve("recovered-functions.jsonl"));BufferedWriter refs=Files.newBufferedWriter(out.resolve("recovered-function-references.jsonl"))) {
            for(Address a:added) {
                Function f=fm.getFunctionAt(a);DecompileResults r=d.decompileFunction(f,10,monitor);boolean success=r.decompileCompleted()&&r.getDecompiledFunction()!=null;
                if(success){Files.writeString(out.resolve("decompiled/"+a+".c"),"/* Recovered callback "+a+" */\n"+r.getDecompiledFunction().getC(),StandardCharsets.UTF_8);ok++;}else failed++;
                index.write(obj("address",a,"function",f.getName(true),"body",f.getBody(),"decompiled",success,"error",r.getErrorMessage()));index.newLine();
                InstructionIterator it=listing.getInstructions(f.getBody(),true);
                while(it.hasNext()){Instruction ins=it.next();for(Reference ref:ins.getReferencesFrom()){refs.write(obj("function",a,"instruction",ins.getAddress(),"text",ins,"reference_type",ref.getReferenceType(),"target",ref.getToAddress()));refs.newLine();}}
            }
        }finally{d.dispose();}
        Files.writeString(out.resolve("coverage.json"),obj("original_function_count",before.size(),"final_function_count",after.size(),"added_functions",added.size(),"data_code_pointer_candidates",pointerCount,"heuristic_mfc_entries",mapCount,"recovery_candidates",recover.size(),"closure_attempts",closureAttempts,"closure_round_limit",3,"closure_function_cap",1000,"decompiled_added",ok,"failed_added",failed,"cancelled",monitor.isCancelled(),"limits","Raw aligned pointers are candidate evidence; computed/un-aligned/runtime-created targets can remain unknown. MFC/vtable/init classifications require manual confirmation. Code-pointer/callee closure is bounded to three rounds and 1000 new functions; unvisited edges remain reviewable in exported references. Recovery changes Ghidra analysis metadata, not bytes. Original full-analysis output remains separate."));
        println("Callback recovery: original="+before.size()+" added="+added.size()+" candidates="+pointerCount+" output="+out);
    }
}
