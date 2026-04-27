package com.xssframework.detector.java;

import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
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
 * Detects REST endpoint response-body sanitization gaps.
 *
 * Flags @RestController or @ResponseBody methods that:
 *   1. Return a non-primitive, non-void type (i.e., a domain object or collection)
 *      that likely contains user-controlled String fields.
 *   2. Have no sanitization call in the method body.
 *   3. Return entity class names that pattern-match to persistence objects
 *      (contain "Entity", "Model", "Domain", or are annotated-type returns).
 *
 * This targets stored XSS: user POSTs bio → stored in DB → GET returns raw bio in JSON.
 */
public final class RestSanitizationDetector implements Detector {

    // Class name suffixes that suggest a JPA entity is being returned directly
    private static final Set<String> ENTITY_SUFFIXES = Set.of(
            "Entity", "Model", "Domain", "Record", "Document", "Dto", "DTO"
    );

    // Known sanitizer names — if any appear in the method body, we skip it
    private static final Set<String> SANITIZERS = Set.of(
            "htmlEscape", "escapeHtml4", "escapeHtml", "sanitize", "encode",
            "encodeForHTML", "escapeXml", "htmlEncode"
    );

    @Override
    public List<Finding> detect(ParsedFile parsedFile) {
        List<Finding> findings = new ArrayList<>();
        parsedFile.getCompilationUnit().ifPresent(cu ->
                cu.accept(new RestVisitor(parsedFile, findings), null));
        return findings;
    }

    @Override
    public boolean supports(ParsedFile.FileType fileType) {
        return fileType == ParsedFile.FileType.JAVA;
    }

    // ── AST Visitor ──────────────────────────────────────────────────────────

    private static final class RestVisitor extends VoidVisitorAdapter<Void> {

        private final ParsedFile file;
        private final List<Finding> findings;
        private boolean inRestController = false;

        RestVisitor(ParsedFile file, List<Finding> findings) {
            this.file = file;
            this.findings = findings;
        }

        @Override
        public void visit(ClassOrInterfaceDeclaration classDecl, Void arg) {
            boolean wasRest = inRestController;
            inRestController = hasAnnotation(classDecl.getAnnotations(), "RestController")
                    || hasAnnotation(classDecl.getAnnotations(), "Controller");
            super.visit(classDecl, arg);
            inRestController = wasRest;
        }

        @Override
        public void visit(MethodDeclaration method, Void arg) {
            super.visit(method, arg);

            // Only flag methods in @RestController or methods with @ResponseBody
            boolean isResponseBody = hasAnnotation(method.getAnnotations(), "ResponseBody")
                    || hasAnnotation(method.getAnnotations(), "GetMapping")
                    || hasAnnotation(method.getAnnotations(), "PostMapping")
                    || hasAnnotation(method.getAnnotations(), "RequestMapping");

            if (!inRestController && !isResponseBody) return;

            // Check return type — skip void, primitives, ResponseEntity<String>
            String returnType = method.getTypeAsString();
            if (returnType.equals("void") || returnType.equals("String")
                    || isPrimitive(returnType)) return;

            // Check if return type looks like a domain entity
            if (!looksLikeEntityReturn(returnType)) return;

            // Check if method body contains a sanitization call
            String bodyStr = method.getBody().map(Object::toString).orElse("");
            if (containsSanitizer(bodyStr)) return;

            int line = method.getBegin().map(p -> p.line).orElse(0);
            String snippet = file.getLine(line - 1).trim();
            String desc = "REST endpoint '" + method.getNameAsString() +
                    "' returns type '" + returnType + "' which may contain user-controlled String fields " +
                    "without sanitization. This can expose a stored XSS vector via JSON response.";

            findings.add(Finding.builder()
                    .filePath(file.getPath())
                    .lineNumber(line)
                    .type(VulnerabilityType.UNSANITIZED_REST_RESPONSE)
                    .description(desc)
                    .threatScore(ThreatScorer.score(VulnerabilityType.UNSANITIZED_REST_RESPONSE, desc))
                    .suggestion(SuggestionProvider.getSuggestion(VulnerabilityType.UNSANITIZED_REST_RESPONSE, snippet))
                    .codeSnippet(snippet)
                    .build());
        }

        private boolean hasAnnotation(List<AnnotationExpr> annotations, String name) {
            return annotations.stream().anyMatch(a -> a.getNameAsString().equals(name));
        }

        private boolean looksLikeEntityReturn(String returnType) {
            // Strip generics: List<UserEntity> → UserEntity
            String base = returnType.replaceAll(".*<(.*)>.*", "$1").trim();
            if (base.isEmpty()) base = returnType;
            for (String suffix : ENTITY_SUFFIXES) {
                if (base.contains(suffix)) return true;
            }
            // ResponseEntity<SomeThing> — check inner type
            if (returnType.startsWith("ResponseEntity")) {
                String inner = returnType.replaceAll("ResponseEntity<(.*)>", "$1").trim();
                return looksLikeEntityReturn(inner);
            }
            return false;
        }

        private boolean isPrimitive(String type) {
            return Set.of("int","long","double","float","boolean","char","byte","short",
                    "Integer","Long","Double","Float","Boolean","Character","Byte","Short").contains(type);
        }

        private boolean containsSanitizer(String body) {
            String lower = body.toLowerCase();
            return SANITIZERS.stream().anyMatch(s -> lower.contains(s.toLowerCase()));
        }
    }
}