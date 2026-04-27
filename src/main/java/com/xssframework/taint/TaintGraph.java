package com.xssframework.taint;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stateful cross-file registry of tainted symbols.
 *
 * During phase 1 of the scan, JavaSourceAnalyzer registers every
 * @RequestParam / @RequestBody parameter found in controllers.
 * During phase 2, TaintFlowDetector queries this graph to find
 * tainted symbols that reach repositories or response objects
 * without being sanitized.
 *
 * Key: "ClassName#methodName#variableName"
 */
public final class TaintGraph {

    // Canonical key → tainted symbol
    private final Map<String, TaintedSymbol> symbols = new ConcurrentHashMap<>();

    // Tracks method call edges: "CallerClass#callerMethod" → List<"CalleeClass#calleeMethod">
    private final Map<String, List<String>> callEdges = new ConcurrentHashMap<>();

    // ── Registration ────────────────────────────────────────────────────────

    public void registerSymbol(TaintedSymbol symbol) {
        String key = buildSymbolKey(symbol.getDeclaringClass(), symbol.getDeclaringMethod(), symbol.getVariableName());
        symbols.put(key, symbol);
    }

    public void registerCallEdge(String callerClass, String callerMethod,
                                 String calleeClass, String calleeMethod) {
        String callerKey = callerClass + "#" + callerMethod;
        String calleeKey = calleeClass + "#" + calleeMethod;
        callEdges.computeIfAbsent(callerKey, k -> new ArrayList<>()).add(calleeKey);
    }

    public void markSanitized(String className, String methodName, String varName, String sanitizer) {
        String key = buildSymbolKey(className, methodName, varName);
        TaintedSymbol sym = symbols.get(key);
        if (sym != null) {
            sym.markSanitized(sanitizer);
        }
    }

    // ── Queries ─────────────────────────────────────────────────────────────

    /** Returns all unsanitized tainted symbols registered so far. */
    public List<TaintedSymbol> getUnsanitizedSymbols() {
        return symbols.values().stream()
                .filter(s -> !s.isSanitized())
                .toList();
    }

    /** Returns all symbols declared in a specific class + method. */
    public List<TaintedSymbol> getSymbolsInMethod(String className, String methodName) {
        String prefix = className + "#" + methodName + "#";
        return symbols.entrySet().stream()
                .filter(e -> e.getKey().startsWith(prefix))
                .map(Map.Entry::getValue)
                .toList();
    }

    /** Returns the call-graph edges reachable from a given caller. */
    public List<String> getCallees(String callerClass, String callerMethod) {
        return callEdges.getOrDefault(callerClass + "#" + callerMethod, Collections.emptyList());
    }

    public boolean hasSymbols() {
        return !symbols.isEmpty();
    }

    public void clear() {
        symbols.clear();
        callEdges.clear();
    }

    // ── Internals ────────────────────────────────────────────────────────────

    private static String buildSymbolKey(String cls, String method, String var) {
        return cls + "#" + method + "#" + var;
    }
}