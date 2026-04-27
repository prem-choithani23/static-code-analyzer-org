package com.xssframework.suggestion;

import com.xssframework.model.VulnerabilityType;

import java.util.EnumMap;
import java.util.Map;

/**
 * Returns a fix suggestion string for each VulnerabilityType.
 *
 * DESIGN NOTE — AI SWAP POINT:
 * This class is the single place where suggestions are generated.
 * To upgrade from static suggestions to AI-generated ones:
 *   1. Inject an AiClient dependency into this class.
 *   2. Replace the Map lookup in getSuggestion() with an API call
 *      that passes the faulty code snippet + vulnerability context.
 *   3. Nothing in Finding, the detectors, or the report generator changes.
 *
 * The method signature stays identical: getSuggestion(VulnerabilityType, String codeSnippet)
 */
public final class SuggestionProvider {

    private static final Map<VulnerabilityType, String> SUGGESTIONS =
            new EnumMap<>(VulnerabilityType.class);

    static {
        SUGGESTIONS.put(VulnerabilityType.XSS,
                "Sanitize all user-controlled output before writing to the response. " +
                        "Use HtmlUtils.htmlEscape(value) from Spring or StringEscapeUtils.escapeHtml4() from Apache Commons Text. " +
                        "For Thymeleaf, always prefer th:text over th:utext unless you have explicitly validated the content as safe HTML. " +
                        "Never concatenate user input into a response.getWriter().write() call.");

        SUGGESTIONS.put(VulnerabilityType.SQL_INJECTION,
                "Replace all string-concatenated SQL queries with parameterized queries or Spring Data JPA named parameters. " +
                        "Use @Query(\"SELECT u FROM User u WHERE u.name = :name\") with @Param(\"name\"), or switch to JPA Criteria API. " +
                        "For raw JDBC, use PreparedStatement with '?' placeholders — never Statement.execute(\"... \" + userInput). " +
                        "Validate and reject inputs that contain SQL metacharacters as an additional layer.");

        SUGGESTIONS.put(VulnerabilityType.INSECURE_CONFIG,
                "Review each flagged property: " +
                        "(1) JWT secrets must be at least 256 bits (32 characters of high entropy) — store them in environment variables or Vault, not in application.properties. " +
                        "(2) spring.security.enabled=false must never appear in a production profile. " +
                        "(3) management.endpoints.web.exposure.include=* exposes actuator endpoints publicly; restrict to 'health,info' unless running behind an internal gateway with auth. " +
                        "(4) server.ssl.enabled=false is only acceptable in local development; enforce TLS in staging and production.");

        SUGGESTIONS.put(VulnerabilityType.TEMPLATE_XSS,
                "In Thymeleaf templates, replace th:utext with th:text for all user-controlled values — th:text escapes HTML automatically. " +
                        "Never inline ${variable} expressions directly inside <script> blocks; pass data via data-* attributes and read them from JavaScript. " +
                        "For JSP files, replace <%= expression %> with <c:out value=\"${expression}\" escapeXml=\"true\" /> using JSTL. " +
                        "Audit every template file for raw EL expressions in event handlers (onclick=\"${...}\").");

        SUGGESTIONS.put(VulnerabilityType.UNSANITIZED_REST_RESPONSE,
                "Before returning an entity or DTO from a @RestController, ensure any field that was populated from user input has been sanitized. " +
                        "Prefer dedicated response DTOs over returning JPA entities directly — this prevents accidental exposure of internal fields. " +
                        "Add a sanitization step in the service layer (e.g., entity.setBio(HtmlUtils.htmlEscape(entity.getBio()))) before returning. " +
                        "Consider a global @ControllerAdvice that sanitizes outgoing response fields using reflection or a DTO mapper.");

        SUGGESTIONS.put(VulnerabilityType.TAINT_FLOW,
                "Tainted data from @RequestParam or @RequestBody is flowing to a persistence layer or response without a sanitization checkpoint. " +
                        "Add an explicit sanitization step in the @Service method before passing data to the @Repository. " +
                        "For HTML-destined fields, use HtmlUtils.htmlEscape(). " +
                        "For SQL-bound parameters, ensure you are using Spring Data's @Param binding or JPA's setParameter(), never concatenation. " +
                        "Consider using a validation framework (Jakarta Bean Validation) with @NotNull, @Size, and custom @SafeHtml constraints at the controller layer.");
    }

    private SuggestionProvider() {}

    /**
     * Returns the fix suggestion for the given vulnerability type.
     *
     * @param type        the detected vulnerability category
     * @param codeSnippet the offending code (reserved for future AI integration)
     * @return a human-readable fix suggestion string
     */
    public static String getSuggestion(VulnerabilityType type, String codeSnippet) {
        // Future: if aiClient != null, call aiClient.suggest(type, codeSnippet)
        return SUGGESTIONS.getOrDefault(type, "Review this code for security vulnerabilities and apply appropriate input validation and output encoding.");
    }
}