// Whole-program static inventory plus bounded decompilation. No program mutation.
// @category GuliKit.Audit
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class AuditWholeProgram extends GhidraScript {
  private Path out;
  private final Set<Address> selected = new TreeSet<>();
  private final Map<Address, Set<String>> reasons = new TreeMap<>();
  private final Map<Address, Set<String>> watched = new TreeMap<>();
  private long functionCount, symbolCount, callCount, computedCallCount, callbackCount;
  private long decompiledCount, failedCount;
  private static final String API_RE =
      "(?i).*(deviceusb|createfile|deviceiocontrol|readfile|writefile|getdrivetype|getlogicaldrive|sleep|createthread|beginthread|loadlibrary|getprocaddress|closehandle|createmutex|waitfor|setevent|resumethread|suspendthread|settimer|killtimer|lockfile|unlockfile|flushfilebuffers|setfilepointer|getvolumeinformation|setupdi|winusb|hid[dD]?_|usb|registerdevice|devicenotification|virtualprotect|virtualalloc).*";

  private Map<String, Object> row(Object... pairs) {
    Map<String, Object> m = new LinkedHashMap<>();
    for (int i = 0; i < pairs.length; i += 2) m.put((String) pairs[i], pairs[i + 1]);
    return m;
  }

  private String addr(Address a) {
    return a == null ? null : a.toString();
  }

  private String fn(Function f) {
    return f == null ? null : f.getName(true);
  }

  private String json(Object o) {
    if (o == null) return "null";
    if (o instanceof Boolean || o instanceof Number) return o.toString();
    if (o instanceof Map) {
      StringBuilder s = new StringBuilder("{");
      boolean first = true;
      for (Object x : ((Map<?, ?>) o).entrySet()) {
        Map.Entry<?, ?> e = (Map.Entry<?, ?>) x;
        if (!first) s.append(',');
        first = false;
        s.append(json(e.getKey().toString())).append(':').append(json(e.getValue()));
      }
      return s.append('}').toString();
    }
    if (o instanceof Iterable) {
      StringBuilder s = new StringBuilder("[");
      boolean first = true;
      for (Object x : (Iterable<?>) o) {
        if (!first) s.append(',');
        first = false;
        s.append(json(x));
      }
      return s.append(']').toString();
    }
    StringBuilder s = new StringBuilder("\"");
    for (char c : o.toString().toCharArray()) {
      switch (c) {
        case '\\':
          s.append("\\\\");
          break;
        case '"':
          s.append("\\\"");
          break;
        case '\n':
          s.append("\\n");
          break;
        case '\r':
          s.append("\\r");
          break;
        case '\t':
          s.append("\\t");
          break;
        default:
          if (c < 32) s.append(String.format("\\u%04x", (int) c));
          else s.append(c);
      }
    }
    return s.append('"').toString();
  }

  private BufferedWriter writer(String name) throws IOException {
    return Files.newBufferedWriter(out.resolve(name), StandardCharsets.UTF_8);
  }

  private void emit(BufferedWriter w, Object value) throws IOException {
    w.write(json(value));
    w.newLine();
  }

  private void select(Function f, String why) {
    if (f == null || f.isExternal()) return;
    Address a = f.getEntryPoint();
    selected.add(a);
    reasons.computeIfAbsent(a, k -> new TreeSet<>()).add(why);
  }

  private void watch(Address a, String why) {
    watched.computeIfAbsent(a, k -> new TreeSet<>()).add(why);
  }

  private Map<String, Object> refRow(Reference r) {
    Function owner = getFunctionContaining(r.getFromAddress());
    Symbol target = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
    return row(
        "from",
        addr(r.getFromAddress()),
        "to",
        addr(r.getToAddress()),
        "type",
        r.getReferenceType().toString(),
        "operand",
        r.getOperandIndex(),
        "source",
        r.getSource().toString(),
        "caller",
        fn(owner),
        "caller_entry",
        owner == null ? null : addr(owner.getEntryPoint()),
        "target_symbol",
        target == null ? null : target.getName(true));
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length == 0)
      throw new IllegalArgumentException(
          "Usage: AuditWholeProgram.java OUTPUT_DIRECTORY [full] [timeout_seconds]");
    out = Paths.get(args[0]);
    Files.createDirectories(out);
    Files.createDirectories(out.resolve("decompiled"));
    boolean full = args.length > 1 && args[1].equalsIgnoreCase("full");
    int timeout = args.length > 2 ? Integer.parseInt(args[2]) : 10;
    boolean dll = currentProgram.getImageBase().getOffset() == 0x10000000L;
    FunctionManager fm = currentProgram.getFunctionManager();
    ReferenceManager rm = currentProgram.getReferenceManager();
    SymbolTable st = currentProgram.getSymbolTable();

    try (BufferedWriter w = writer("symbols.jsonl")) {
      SymbolIterator syms = st.getAllSymbols(true);
      while (syms.hasNext() && !monitor.isCancelled()) {
        Symbol s = syms.next();
        symbolCount++;
        emit(
            w,
            row(
                "address",
                addr(s.getAddress()),
                "name",
                s.getName(true),
                "type",
                s.getSymbolType().toString(),
                "source",
                s.getSource().toString(),
                "external",
                s.isExternal()));
        if (s.getName(true).matches(API_RE)) watch(s.getAddress(), "API/symbol:" + s.getName(true));
      }
    }
    // Function-pointer slots are watched for all reads/writes, not just calls.
    if (!dll)
      for (long a = 0x5f985cL; a <= 0x5f9874L; a += 4) watch(toAddr(a), "application-global-slot");
    try (BufferedWriter w = writer("entrypoints.jsonl")) {
      AddressIterator entries = st.getExternalEntryPointIterator();
      while (entries.hasNext()) {
        Address a = entries.next();
        Function f = fm.getFunctionAt(a);
        emit(w, row("address", addr(a), "function", fn(f)));
        select(f, "entrypoint/export");
      }
    }
    try (BufferedWriter w = writer("watched-references.jsonl")) {
      // Follow imported external symbol -> IAT cell -> thunk/caller, bounded
      // to three reference hops. Every hop is written; no dynamic target is invented.
      Map<Address, Set<String>> frontier = new TreeMap<>(watched);
      Set<Address> visited = new HashSet<>();
      for (int depth = 0; depth < 3; depth++) {
        Map<Address, Set<String>> next = new TreeMap<>();
        for (Map.Entry<Address, Set<String>> e : frontier.entrySet()) {
          if (!visited.add(e.getKey())) continue;
          ReferenceIterator refs = rm.getReferencesTo(e.getKey());
          while (refs.hasNext()) {
            Reference r = refs.next();
            Map<String, Object> record = refRow(r);
            record.put("watched_reasons", e.getValue());
            record.put("reference_depth", depth);
            emit(w, record);
            Function owner = fm.getFunctionContaining(r.getFromAddress());
            select(owner, "watched-reference:" + e.getKey());
            if (owner != null) {
              if (owner.isThunk())
                next.computeIfAbsent(owner.getEntryPoint(), k -> new TreeSet<>())
                    .addAll(e.getValue());
            } else if (r.getFromAddress().isMemoryAddress()) {
              next.computeIfAbsent(r.getFromAddress(), k -> new TreeSet<>()).addAll(e.getValue());
            }
          }
        }
        frontier = next;
      }
    }
    try (BufferedWriter funcs = writer("functions.jsonl");
        BufferedWriter graph = writer("function-callgraph.jsonl");
        BufferedWriter callbacks = writer("function-entry-references.jsonl")) {
      FunctionIterator it = fm.getFunctions(true);
      while (it.hasNext() && !monitor.isCancelled()) {
        Function f = it.next();
        functionCount++;
        long a = f.getEntryPoint().getOffset();
        if (full || dll) select(f, full ? "full-mode" : "all-DLL-functions");
        else if (a >= 0x401000L && a < 0x404000L) select(f, "custom-application-range");
        Function thunk = f.isThunk() ? f.getThunkedFunction(true) : null;
        emit(
            funcs,
            row(
                "entry",
                addr(f.getEntryPoint()),
                "name",
                fn(f),
                "body",
                f.getBody().toString(),
                "size",
                f.getBody().getNumAddresses(),
                "signature",
                f.getSignature().toString(),
                "calling_convention",
                f.getCallingConventionName(),
                "external",
                f.isExternal(),
                "thunk",
                f.isThunk(),
                "thunk_target",
                thunk == null ? null : addr(thunk.getEntryPoint())));
        for (Function callee : f.getCalledFunctions(monitor))
          emit(
              graph,
              row(
                  "caller",
                  addr(f.getEntryPoint()),
                  "caller_name",
                  fn(f),
                  "callee",
                  addr(callee.getEntryPoint()),
                  "callee_name",
                  fn(callee)));
        ReferenceIterator refs = rm.getReferencesTo(f.getEntryPoint());
        while (refs.hasNext()) {
          Reference r = refs.next();
          Map<String, Object> record = refRow(r);
          record.put("function_entry", addr(f.getEntryPoint()));
          record.put("possible_callback_or_pointer", !r.getReferenceType().isFlow());
          if (!r.getReferenceType().isFlow()) callbackCount++;
          emit(callbacks, record);
        }
      }
    }
    try (BufferedWriter calls = writer("callsites.jsonl");
        BufferedWriter indirect = writer("indirect-calls.jsonl")) {
      InstructionIterator it = currentProgram.getListing().getInstructions(true);
      while (it.hasNext() && !monitor.isCancelled()) {
        Instruction ins = it.next();
        if (!ins.getFlowType().isCall()) continue;
        callCount++;
        List<Object> refs = new ArrayList<>();
        for (Reference r : ins.getReferencesFrom()) refs.add(refRow(r));
        Function owner = fm.getFunctionContaining(ins.getAddress());
        Map<String, Object> record =
            row(
                "address",
                addr(ins.getAddress()),
                "instruction",
                ins.toString(),
                "flow_type",
                ins.getFlowType().toString(),
                "computed",
                ins.getFlowType().isComputed(),
                "caller",
                fn(owner),
                "caller_entry",
                owner == null ? null : addr(owner.getEntryPoint()),
                "references",
                refs);
        emit(calls, record);
        if (ins.getFlowType().isComputed()) {
          computedCallCount++;
          record.put(
              "coverage_note",
              "Static references do not prove a unique runtime call target; inspect decompiled"
                  + " dataflow and callbacks.");
          emit(indirect, record);
        }
      }
    }

    DecompInterface decomp = new DecompInterface();
    decomp.toggleCCode(true);
    decomp.toggleSyntaxTree(true);
    decomp.setSimplificationStyle("decompile");
    if (!decomp.openProgram(currentProgram))
      throw new IOException("Decompiler open failed: " + decomp.getLastMessage());
    try (BufferedWriter index = writer("decompilation-index.jsonl")) {
      for (Address a : selected) {
        if (monitor.isCancelled()) break;
        Function f = fm.getFunctionAt(a);
        if (f == null) continue;
        monitor.setMessage("Decompiling " + f.getName() + " @ " + a);
        DecompileResults result = decomp.decompileFunction(f, timeout, monitor);
        boolean ok = result.decompileCompleted() && result.getDecompiledFunction() != null;
        String file = "decompiled/" + a.toString().replace(':', '_') + ".c";
        if (ok) {
          Files.writeString(
              out.resolve(file),
              "/* "
                  + fn(f)
                  + " @ "
                  + a
                  + "; selection: "
                  + reasons.get(a)
                  + " */\n"
                  + result.getDecompiledFunction().getC(),
              StandardCharsets.UTF_8);
          decompiledCount++;
        } else failedCount++;
        emit(
            index,
            row(
                "address",
                addr(a),
                "function",
                fn(f),
                "reasons",
                reasons.get(a),
                "completed",
                ok,
                "error",
                result.getErrorMessage(),
                "output",
                ok ? file : null));
        index.flush();
      }
    } finally {
      decomp.dispose();
    }
    Files.writeString(
        out.resolve("coverage.json"),
        json(
            row(
                "program",
                currentProgram.getName(),
                "executable_path",
                currentProgram.getExecutablePath(),
                "image_base",
                addr(currentProgram.getImageBase()),
                "language",
                currentProgram.getLanguageID().toString(),
                "compiler_spec",
                currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
                "full_decompile",
                full,
                "dll_all_functions",
                dll,
                "per_function_timeout_seconds",
                timeout,
                "function_count",
                functionCount,
                "symbol_count",
                symbolCount,
                "callsites",
                callCount,
                "computed_callsites",
                computedCallCount,
                "non_flow_function_entry_references",
                callbackCount,
                "selected_functions",
                selected.size(),
                "decompiled_functions",
                decompiledCount,
                "failed_decompilations",
                failedCount,
                "cancelled",
                monitor.isCancelled(),
                "limits",
                Arrays.asList(
                    "Inventory covers all Ghidra-discovered functions and instructions;"
                        + " undiscovered code may remain.",
                    "Computed calls and data references are exported, not asserted uniquely"
                        + " resolved.",
                    "Non-flow entry references are possible callbacks/pointers; callback semantics"
                        + " require review.",
                    "Default EXE decompilation includes application range, entrypoints, and watched"
                        + " I/O callers; full adds all discovered functions.",
                    "Windows kernel and actual USB wire behavior are outside these PE files.",
                    "Decompiler output is an analysis artifact; corroborate disputed details with"
                        + " instruction bytes."))),
        StandardCharsets.UTF_8);
    println(
        "Audit complete: "
            + out
            + " functions="
            + functionCount
            + " decompiled="
            + decompiledCount
            + " failures="
            + failedCount
            + " indirect_calls="
            + computedCallCount);
  }
}
