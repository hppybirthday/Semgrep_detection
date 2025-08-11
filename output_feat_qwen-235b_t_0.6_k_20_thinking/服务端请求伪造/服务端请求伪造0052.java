import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.function.*;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/joblog")
public class LogProcessor {
    
    @PostMapping("/logDetailCat")
    public CompletableFuture<String> processLog(@RequestParam String url) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                URL target = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) target.openConnection();
                conn.setRequestMethod("GET");
                
                if (conn.getResponseCode() == 200) {
                    String result = new BufferedReader(new InputStreamReader(conn.getInputStream()))
                        .lines().reduce((a, b) -> a + "\
" + b).orElse("");
                    
                    // Simulate uploading image data to internal service
                    if (result.contains("image/png")) {
                        uploadToInternalService(result);
                    }
                    return "Processed log content: " + result.substring(0, Math.min(100, result.length()));
                }
                return "Failed to fetch log details";
            } catch (Exception e) {
                return "Error processing request: " + e.getMessage();
            }
        });
    }

    private void uploadToInternalService(String data) throws IOException {
        // Simulated internal service upload
        String internalUrl = "http://ace-admin/internal/upload";
        HttpURLConnection conn = (HttpURLConnection) new URL(internalUrl).openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        
        try (OutputStream os = conn.getOutputStream()) {
            os.write(data.getBytes());
        }
    }

    // Vulnerable endpoint for SSRF demonstration
    @GetMapping("/logKill")
    public Function<String, String> killLogProcess = (url) -> {
        return (String) (input -> {
            try {
                URL target = new URL(input);
                return "Connecting to target: " + target.getHost() + ", Response code: " + 
                       ((HttpURLConnection) target.openConnection()).getResponseCode();
            } catch (Exception e) {
                return "Connection failed: " + e.getMessage();
            }
        }).apply(url);
    };
}