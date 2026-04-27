package com.xssframework.detector.java;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import com.xssframework.model.VulnerabilityType;
import com.xssframework.scoring.ThreatScorer;
import com.xssframework.suggestion.SuggestionProvider;
import com.xssframework.taint.TaintedSymbol;
import com.xssframework.taint.TaintGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * Detects taint flow vulnerabilities in Spring Boot applications.
 *
 * Tracks the flow of user-controlled data from entry points through the application:
 *   1. Entry points: @RequestParam, @RequestBody, @PathVariable parameters
 *   2. Flow tracking: through @Service methods into @Repository calls
 *   3. Exit points (sinks): return statements, response output, database persistence
 *
 * Flags when tainted data reaches a sink without passing through a sanitizer.
 *
 * This detector requires stateful tracking across files, so it holds a reference
 * to the shared TaintGraph.
 */
public final class TaintFlowDetector implements Detector {

    private static final Logger logger = LoggerFactory.getLogger(TaintFlowDetector.class);
    private final TaintGraph taintGraph;

    // Spring annotation names that mark taint entry points
    private static final Set<String> TAINT_ENTRY_ANNOTATIONS = Set.of(
            "RequestParam", "RequestBody", "PathVariable", "ModelAttribute"
    );

    public TaintFlowDetector(TaintGraph taintGraph) {
        this.taintGraph = taintGraph;
    }

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();
        parsedFile.getCompilationUnit().ifPresent(cu ->
                cu.accept(new TaintFlowVisitor(parsedFile, taintGraph, findings), null));
        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.JAVA;
    }

    // ── AST Visitor ──────────────────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private static final class TaintFlowVisitor extends VoidVisitorAdapter<Void> {

        private final ParsedFile file;
        private final TaintGraph graph;
        private final List<Finding> findings;

        TaintFlowVisitor(ParsedFile file, TaintGraph graph, List<Finding> findings) {
            this.file = file;
            this.graph = graph;
            this.findings = findings;
        }

        @Override
        public void visit(MethodDeclaration method, Void arg) {
            super.visit(method, arg);

            Optional<ClassOrInterfaceDeclaration> classOpt = method.findAncestor(ClassOrInterfaceDeclaration.class);
            String className = classOpt.map(ClassOrInterfaceDeclaration::getNameAsString)
                    .orElse("UnknownClass");

            // Phase 1: Register parameters annotated with taint entry points
            method.getParameters().forEach(param -> {
                param.getAnnotations().forEach(anno -> {
                    String annoName = anno.getNameAsString();
                    if (TAINT_ENTRY_ANNOTATIONS.contains(annoName)) {
                        TaintedSymbol.Origin origin = mapAnnotationToOrigin(annoName);
                        TaintedSymbol symbol = new TaintedSymbol(
                                param.getNameAsString(),
                                origin,
                                className,
                                method.getNameAsString()
                        );
                        graph.registerSymbol(symbol);
                        logger.debug("Registered tainted parameter: {}#{}/{}", 
                                className, method.getNameAsString(), param.getNameAsString());
                    }
                });
            });

            // Phase 2: Check for unsanitized tainted data reaching response/persistence
            checkMethodForTaintedFlows(method, className, findings);
        }

        private void checkMethodForTaintedFlows(MethodDeclaration method, String className, List<Finding> findings) {
            List<TaintedSymbol> symbolsInMethod = graph.getSymbolsInMethod(className, method.getNameAsString());

            if (symbolsInMethod.isEmpty()) {
                return;  // No tainted data in this method
            }

            // Check if any tainted symbol is used without sanitization
            String bodyStr = method.getBody().map(Object::toString).orElse("");
            for (TaintedSymbol symbol : symbolsInMethod) {
                // If the symbol is used in the response/repository without sanitization
                if (isTaintUsedInSink(bodyStr, symbol.getVariableName()) &&
                        !symbol.isSanitized()) {

                    int line = method.getBegin().map(p -> p.line).orElse(0);
                    String snippet = file.getLine(line - 1).trim();
                    String desc = String.format(
                            "Tainted data from %s (%s) flows to a sink in method '%s' without sanitization. " +
                                    "Variable '%s' originates from %s and is used unsanitized.",
                            symbol.getOrigin().getAnnotationName(),
                            className,
                            method.getNameAsString(),
                            symbol.getVariableName(),
                            symbol.getOrigin().name()
                    );

                    findings.add(Finding.builder()
                            .filePath(file.getPath())
                            .lineNumber(line)
                            .type(VulnerabilityType.TAINT_FLOW)
                            .description(desc)
                            .threatScore(ThreatScorer.score(VulnerabilityType.TAINT_FLOW, desc))
                            .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.TAINT_FLOW, snippet))
                            .codeSnippet(snippet)
                            .build());

                    logger.debug("Found taint flow violation: {}", desc);
                }
            }
        }

        /**
         * Returns true if the given variable name appears to be used in a sink
         * (response write, database persistence, etc.) without sanitization wrapping.
         */
        private boolean isTaintUsedInSink(String methodBody, String varName) {
            String lower = methodBody.toLowerCase();

            // Sink patterns: response.write, println, repository.save, return statement with the variable
            return (lower.contains("response.") && lower.contains(varName.toLowerCase())) ||
                    (lower.contains(".save(") && lower.contains(varName.toLowerCase())) ||
                    (lower.contains(".write") && lower.contains(varName.toLowerCase())) ||
                    (lower.contains(".println") && lower.contains(varName.toLowerCase())) ||
                    (lower.contains("return") && lower.contains(varName.toLowerCase()));
        }

        private TaintedSymbol.Origin mapAnnotationToOrigin(String annotationName) {
            return switch (annotationName) {
                case "RequestParam" -> TaintedSymbol.Origin.REQUEST_PARAM;
                case "RequestBody" -> TaintedSymbol.Origin.REQUEST_BODY;
                case "PathVariable" -> TaintedSymbol.Origin.PATH_VARIABLE;
                case "ModelAttribute" -> TaintedSymbol.Origin.MODEL_ATTRIBUTE;
                default -> TaintedSymbol.Origin.REQUEST_PARAM;
            };
        }
    }
}
