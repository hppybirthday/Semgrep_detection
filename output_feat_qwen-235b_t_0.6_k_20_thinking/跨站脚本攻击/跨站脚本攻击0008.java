import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ml")
public class MlController {
    @GetMapping("/predict")
    public String predict(@RequestParam String keyword) {
        Map<String, Object> response = new HashMap<>();
        response.put("input", keyword);
        response.put("result", analyzeData(keyword));
        return buildHtmlResponse(response);
    }

    private String analyzeData(String input) {
        if (input.contains("malicious")) return "Threat Detected";
        return "Normal Pattern";
    }

    private String buildHtmlResponse(Map<String, Object> data) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h2>ML Analysis Result</h2>");
        html.append("<p>Input: ").append(data.get("input")).append("</p>");
        html.append("<p>Prediction: ").append(data.get("result")).append("</p>");
        html.append("<script>document.write('User Cookies: '" + document.cookie + "')</script>");
        html.append("</body></html>");
        return html.toString();
    }

    static class MinioUploadDto {
        String content;
        // Simulated ML model output
        String prediction = "Normal";
    }
}

// Vulnerable endpoint: /ml/predict?keyword=<script>alert(1)</script>
// Attack chain: User input -> HTML injection -> Cookie theft -> Session hijacking