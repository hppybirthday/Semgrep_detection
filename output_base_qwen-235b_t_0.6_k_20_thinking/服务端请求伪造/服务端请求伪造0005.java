import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SsrfVulnerableService {

    private static final Map<String, String> PLUGIN_REGISTRY = new HashMap<>();

    static {
        PLUGIN_REGISTRY.put("image", "processImageRequest");
        PLUGIN_REGISTRY.put("data", "processDataRequest");
    }

    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableService.class, args);
    }

    @GetMapping("/proxy/{type}")
    public ResponseEntity<byte[]> dynamicProxyHandler(@PathVariable String type, @RequestParam String resource) throws Exception {
        String methodName = PLUGIN_REGISTRY.getOrDefault(type, "defaultHandler");
        return (ResponseEntity<byte[]>) SsrfVulnerableService.class
            .getDeclaredMethod(methodName, String.class)
            .invoke(this, resource);
    }

    private ResponseEntity<byte[]> processImageRequest(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        if (connection.getResponseCode() != 200) {
            throw new IOException("Image fetch failed with code: " + connection.getResponseCode());
        }

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (InputStream input = connection.getInputStream()) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_JPEG);
        headers.setContentLength(output.size());
        
        return new ResponseEntity<>(output.toByteArray(), headers, HttpStatus.OK);
    }

    private ResponseEntity<byte[]> processDataRequest(String dataSourceUrl) throws IOException {
        // Simulated data processing endpoint that also suffers from SSRF
        return processImageRequest(dataSourceUrl);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        return new ResponseEntity<>("Error: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}