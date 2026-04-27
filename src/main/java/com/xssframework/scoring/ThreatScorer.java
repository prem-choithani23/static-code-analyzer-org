package com.xssframework.scoring;

import com.xssframework.model.Finding;
import com.xssframework.model.VulnerabilityType;

/**
 * Assigns a numeric threat score (1–100) to a vulnerability.
 *
 * Scoring logic considers:
 *   1. Base score for the vulnerability type (reflecting industry CVSS baselines)
 *   2. Context modifiers from the description (e.g., JDBC raw query = +10)
 *   3. Future extension point: pass in runtime context for dynamic scoring
 */
public final class ThreatScorer {

    // Base scores per vulnerability type (calibrated to OWASP severity)
    private static final int BASE_XSS                      = 75;
    private static final int BASE_SQL_INJECTION            = 85;
    private static final int BASE_INSECURE_CONFIG          = 70;
    private static final int BASE_TEMPLATE_XSS             = 80;
    private static final int BASE_UNSANITIZED_REST         = 72;
    private static final int BASE_TAINT_FLOW               = 78;

    private ThreatScorer() {}

    /**
     * Compute the final threat score for a finding.
     * The description is analysed for context keywords that escalate or reduce severity.
     *
     * @param type        the vulnerability category
     * @param description the human-readable finding description
     * @return score in range [1, 100]
     */
    public static int score(VulnerabilityType type, String description) {
        int base = baseScore(type);
        int modifier = contextModifier(description);
        return clamp(base + modifier);
    }

    private static int baseScore(VulnerabilityType type) {
        return switch (type) {
            case XSS                      -> BASE_XSS;
            case SQL_INJECTION            -> BASE_SQL_INJECTION;
            case INSECURE_CONFIG          -> BASE_INSECURE_CONFIG;
            case TEMPLATE_XSS            -> BASE_TEMPLATE_XSS;
            case UNSANITIZED_REST_RESPONSE -> BASE_UNSANITIZED_REST;
            case TAINT_FLOW              -> BASE_TAINT_FLOW;
        };
    }

    /**
     * Context keywords that bump the score up or down.
     * Keeps scoring transparent — no magic numbers buried in detectors.
     */
    private static int contextModifier(String description) {
        if (description == null) return 0;
        String lower = description.toLowerCase();

        int delta = 0;

        // Escalators
        if (lower.contains("password"))               delta += 15;
        if (lower.contains("secret"))                 delta += 12;
        if (lower.contains("jwt"))                    delta += 10;
        if (lower.contains("actuator"))               delta += 10;
        if (lower.contains("ssl disabled"))           delta += 12;
        if (lower.contains("raw jdbc"))               delta += 10;
        if (lower.contains("concatenat"))             delta += 8;
        if (lower.contains("th:utext"))               delta += 8;
        if (lower.contains("script block"))           delta += 10;
        if (lower.contains("stored"))                 delta += 7;   // stored XSS > reflected
        if (lower.contains("@requestbody"))           delta += 5;   // full object deserialization
        if (lower.contains("management.endpoints"))   delta += 8;

        // Mitigators
        if (lower.contains("dev profile"))            delta -= 10;
        if (lower.contains("test"))                   delta -= 5;
        if (lower.contains("readonly"))               delta -= 5;

        return delta;
    }

    private static int clamp(int score) {
        return Math.max(1, Math.min(100, score));
    }
}