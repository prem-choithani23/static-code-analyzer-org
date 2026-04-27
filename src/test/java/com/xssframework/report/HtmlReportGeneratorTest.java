package com.xssframework.report;

import com.xssframework.model.Finding;
import com.xssframework.model.VulnerabilityType;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlReportGeneratorTest {

    @Test
    void generateProducesBalancedEscapedHtml() throws IOException {
        Finding finding = Finding.builder()
                .filePath(Path.of("src/main/resources/templates/bad<script>.html"))
                .lineNumber(9)
                .type(VulnerabilityType.TEMPLATE_XSS)
                .description("Template issue with <script>alert(1)</script> and <b>raw</b> markup")
                .threatScore(88)
                .suggestion("Replace <c:out escapeXml=\"false\"> and <script> usage")
                .codeSnippet("<div th:utext=\"${displayName}\">guest</div>")
                .build();

        Path reportPath = Files.createTempFile("security-report-", ".html");
        try {
            new HtmlReportGenerator().generate(List.of(finding), reportPath);
            String html = Files.readString(reportPath);

            assertTrue(html.contains("<div class=\"container\">"));
            assertEquals(countOccurrences(html, "<div"), countOccurrences(html, "</div>"));
            assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
            assertTrue(html.contains("&lt;div th:utext=&quot;${displayName}&quot;&gt;guest&lt;/div&gt;"));
            assertFalse(html.contains("<td>Template issue with <script>alert(1)</script>"));
        } finally {
            Files.deleteIfExists(reportPath);
        }
    }

    private int countOccurrences(String text, String token) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(token, index)) != -1) {
            count++;
            index += token.length();
        }
        return count;
    }
}
