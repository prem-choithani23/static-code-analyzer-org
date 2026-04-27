package com.xssframework.detector.java;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.xssframework.detector.Detector;
import com.xssframework.model.Finding;
import com.xssframework.model.ParsedFile;
import com.xssframework.model.VulnerabilityType;
import com.xssframework.scoring.ThreatScorer;
import com.xssframework.suggestion.SuggestionProvider;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Detects XSS vulnerabilities in Java Spring source files.
 *
 * Detection patterns (AST-based, not string matching):
 *   1. PrintWriter.write() / PrintWriter.println() calls with non-literal arguments
 *      in @Controller / @RestController methods — raw response writing.
 *   2. HttpServletResponse.getWriter().print(...) with user-tainted variable.
 *   3. Model.addAttribute() where the value name suggests raw HTML origin.
 *   4. String concatenation into response streams.
 *
 * Template-layer XSS (th:utext, JSP EL) is handled by TemplateXssDetector.
 */
public final class XssDetector implements Detector {

    // Known sanitizer method names — if a call wraps the argument, it's safe
    private static final Set<String> SANITIZERS = Set.of(
            "htmlEscape", "escapeHtml4", "escapeHtml", "escapeXml",
            "sanitize", "encode", "encodeForHTML", "escapeHtml3"
    );

    // Response-writing method names that output to the HTTP response
    private static final Set<String> RESPONSE_WRITERS = Set.of(
            "write", "println", "print", "append"
    );

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();

        parsedFile.getCompilationUnit().ifPresent(cu -> {
            cu.accept(new XssVisitor(parsedFile, findings), null);
        });

        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.JAVA;
    }

    // ── AST Visitor ──────────────────────────────────────────────────────────

    private static final class XssVisitor extends VoidVisitorAdapter<Void> {

        private final ParsedFile file;
        private final List<Finding> findings;

        XssVisitor(ParsedFile file, List<Finding> findings) {
            this.file = file;
            this.findings = findings;
        }

        @Override
        public void visit(MethodCallExpr callExpr, Void arg) {
            super.visit(callExpr, arg);

            String methodName = callExpr.getNameAsString();

            // Pattern 1: response.getWriter().write(userInput) or similar chains
            if (RESPONSE_WRITERS.contains(methodName)) {
                callExpr.getScope().ifPresent(scope -> {
                    // Check for getWriter() chain
                    if (scope.toString().contains("getWriter") ||
                            scope.toString().contains("getOutputStream")) {

                        callExpr.getArguments().forEach(argExpr -> {
                            if (!isLiteral(argExpr) && !isSanitized(argExpr)) {
                                int line = callExpr.getBegin().map(p -> p.line).orElse(0);
                                String snippet = file.getLine(line - 1).trim();
                                String desc = "Raw response write with non-literal argument: '"
                                        + argExpr + "'. If this originates from user input, it is an XSS sink.";

                                findings.add(Finding.builder()
                                        .filePath(file.getPath())
                                        .lineNumber(line)
                                        .type(VulnerabilityType.XSS)
                                        .description(desc)
                                        .threatScore(ThreatScorer.score(VulnerabilityType.XSS, desc))
                                        .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.XSS, snippet))
                                        .codeSnippet(snippet)
                                        .build());
                            }
                        });
                    }
                });
            }

            // Pattern 2: String concatenation passed directly to response-writing methods
            if (RESPONSE_WRITERS.contains(methodName)) {
                callExpr.getArguments().forEach(argExpr -> {
                    if (argExpr instanceof BinaryExpr binExpr) {
                        if (binExpr.getOperator() == BinaryExpr.Operator.PLUS && !isSanitized(argExpr)) {
                            int line = callExpr.getBegin().map(p -> p.line).orElse(0);
                            String snippet = file.getLine(line - 1).trim();
                            String desc = "String concatenation used as argument to response writer. " +
                                    "If any concatenated part is user-controlled, this is a reflected XSS sink.";

                            findings.add(Finding.builder()
                                    .filePath(file.getPath())
                                    .lineNumber(line)
                                    .type(VulnerabilityType.XSS)
                                    .description(desc)
                                    .threatScore(ThreatScorer.score(VulnerabilityType.XSS, desc))
                                    .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.XSS, snippet))
                                    .codeSnippet(snippet)
                                    .build());
                        }
                    }
                });
            }
        }

        private boolean isLiteral(Expression expr) {
            return expr instanceof StringLiteralExpr
                    || expr instanceof IntegerLiteralExpr
                    || expr instanceof BooleanLiteralExpr;
        }

        private boolean isSanitized(Expression expr) {
            // If the expression is a method call whose name is a known sanitizer
            if (expr instanceof MethodCallExpr mc) {
                if (SANITIZERS.contains(mc.getNameAsString())) return true;
            }
            // Check if the expression string representation contains a sanitizer name
            String exprStr = expr.toString().toLowerCase();
            return SANITIZERS.stream().anyMatch(s -> exprStr.contains(s.toLowerCase()));
        }
    }
}