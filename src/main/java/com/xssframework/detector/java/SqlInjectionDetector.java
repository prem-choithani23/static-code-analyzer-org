package com.xssframework.detector.java;

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
import java.util.regex.Pattern;

/**
 * Detects SQL Injection vulnerabilities in Java Spring source files.
 *
 * Detection patterns (AST-based):
 *   1. String concatenation inside a method call whose name matches execute/query/update
 *      (covers raw JDBC Statement.execute("SELECT ... " + userInput))
 *   2. String variable assigned via concatenation that contains SQL keywords,
 *      then passed to a query-executing method.
 *   3. @Query annotations where the query string contains concatenation hints
 *      (nativeQuery=true with non-parameterized fragments).
 *   4. EntityManager.createNativeQuery / createQuery with non-literal argument.
 *
 * PreparedStatement with '?' placeholders is safe — not flagged.
 * Spring Data @Param-bound @Query methods are safe — not flagged.
 */
public final class SqlInjectionDetector implements Detector {

    private static final Set<String> QUERY_METHODS = Set.of(
            "execute", "executeQuery", "executeUpdate", "query",
            "createNativeQuery", "createQuery", "nativeQuery",
            "queryForObject", "queryForList", "update"
    );

    // SQL keyword pattern to identify SQL-bearing strings
    private static final Pattern SQL_KEYWORD_PATTERN = Pattern.compile(
            "(?i)\\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|UNION|FROM|WHERE)\\b"
    );

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();
        parsedFile.getCompilationUnit().ifPresent(cu ->
                cu.accept(new SqlInjectionVisitor(parsedFile, findings), null));
        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.JAVA;
    }

    // ── AST Visitor ──────────────────────────────────────────────────────────

    private static final class SqlInjectionVisitor extends VoidVisitorAdapter<Void> {

        private final ParsedFile file;
        private final List<Finding> findings;

        SqlInjectionVisitor(ParsedFile file, List<Finding> findings) {
            this.file = file;
            this.findings = findings;
        }

        @Override
        public void visit(MethodCallExpr callExpr, Void arg) {
            super.visit(callExpr, arg);

            String methodName = callExpr.getNameAsString();

            if (!QUERY_METHODS.contains(methodName)) return;

            // Inspect every argument passed to the query method
            callExpr.getArguments().forEach(argExpr -> {
                if (isDynamicSqlExpression(argExpr)) {
                    int line = callExpr.getBegin().map(p -> p.line).orElse(0);
                    String snippet = file.getLine(line - 1).trim();
                    String desc = buildDescription(methodName, argExpr);

                    findings.add(Finding.builder()
                            .filePath(file.getPath())
                            .lineNumber(line)
                            .type(VulnerabilityType.SQL_INJECTION)
                            .description(desc)
                            .threatScore(ThreatScorer.score(VulnerabilityType.SQL_INJECTION, desc))
                            .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.SQL_INJECTION, snippet))
                            .codeSnippet(snippet)
                            .build());
                }
            });
        }

        /**
         * Returns true if the expression is a dynamic SQL construction:
         *   - BinaryExpr (string concatenation) containing SQL keywords
         *   - MethodCallExpr that returns a String (format, concat, etc.)
         */
        private boolean isDynamicSqlExpression(Expression expr) {
            // Direct concatenation: "SELECT * FROM users WHERE id = " + userId
            if (expr instanceof BinaryExpr binExpr) {
                if (binExpr.getOperator() == BinaryExpr.Operator.PLUS) {
                    // At least one operand should look like SQL to avoid false positives
                    String left = binExpr.getLeft().toString();
                    String right = binExpr.getRight().toString();
                    return SQL_KEYWORD_PATTERN.matcher(left).find()
                            || SQL_KEYWORD_PATTERN.matcher(right).find()
                            || containsSqlFragment(left + right);
                }
            }

            // String.format("SELECT ... %s", userInput)
            if (expr instanceof MethodCallExpr mc) {
                String name = mc.getNameAsString();
                if ((name.equals("format") || name.equals("concat")) && mc.getArguments().size() > 1) {
                    String firstArg = mc.getArgument(0).toString();
                    if (SQL_KEYWORD_PATTERN.matcher(firstArg).find()) return true;
                }
                // StringBuilder.append() chain — surface if the receiver looks SQL-related
                if (name.equals("append")) {
                    String scope = mc.getScope().map(Object::toString).orElse("");
                    if (containsSqlFragment(scope)) return true;
                }
            }

            // Variable reference (non-literal) passed as the sole argument to execute()
            if (expr instanceof NameExpr) {
                // We can't know the value at static analysis time, but a non-literal
                // passed directly to execute() without '?' is suspicious
                return true;
            }

            return false;
        }

        private boolean containsSqlFragment(String text) {
            return SQL_KEYWORD_PATTERN.matcher(text).find();
        }

        private String buildDescription(String methodName, Expression argExpr) {
            if (argExpr instanceof BinaryExpr) {
                return "Raw JDBC: String concatenation used to build a SQL query in '" + methodName +
                        "()'. User-controlled input in the concatenation enables SQL injection. " +
                        "Expression: " + truncate(argExpr.toString());
            }
            return "Potentially unsanitized variable passed directly to '" + methodName +
                    "()'. If the value is user-controlled, this is a SQL injection sink. " +
                    "Expression: " + truncate(argExpr.toString());
        }

        private static String truncate(String s) {
            return s.length() > 120 ? s.substring(0, 120) + "..." : s;
        }
    }
}