package com.xssframework.taint;

/**
 * Represents a single variable that has been flagged as tainted.
 *
 * A symbol becomes tainted when it is bound to a @RequestParam or @RequestBody
 * parameter. It remains tainted until it passes through a known sanitizer
 * (e.g., HtmlUtils.htmlEscape, StringEscapeUtils.escapeHtml4, a PreparedStatement bind).
 */
public final class TaintedSymbol {

    public enum Origin {
        REQUEST_PARAM("@RequestParam"),
        REQUEST_BODY("@RequestBody"),
        PATH_VARIABLE("@PathVariable"),
        MODEL_ATTRIBUTE("@ModelAttribute");

        private final String annotationName;
        Origin(String annotationName) { this.annotationName = annotationName; }
        public String getAnnotationName() { return annotationName; }
    }

    private final String variableName;
    private final Origin origin;
    private final String declaringClass;
    private final String declaringMethod;
    private boolean sanitized;
    private String sanitizerMethod;      // name of the sanitizer, if any

    public TaintedSymbol(String variableName, Origin origin, String declaringClass, String declaringMethod) {
        this.variableName   = variableName;
        this.origin         = origin;
        this.declaringClass = declaringClass;
        this.declaringMethod = declaringMethod;
        this.sanitized       = false;
    }

    /** Mark this symbol as having passed through a sanitizer */
    public void markSanitized(String sanitizerMethod) {
        this.sanitized       = true;
        this.sanitizerMethod = sanitizerMethod;
    }

    public String getVariableName()   { return variableName; }
    public Origin getOrigin()         { return origin; }
    public String getDeclaringClass() { return declaringClass; }
    public String getDeclaringMethod(){ return declaringMethod; }
    public boolean isSanitized()      { return sanitized; }
    public String getSanitizerMethod(){ return sanitizerMethod; }

    @Override
    public String toString() {
        return String.format("TaintedSymbol{name='%s', origin=%s, class='%s', method='%s', sanitized=%b}",
                variableName, origin, declaringClass, declaringMethod, sanitized);
    }
}