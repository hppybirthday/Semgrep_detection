import java.io.*;
import java.net.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class DeviceController {
    private final UrlUploadService uploadService = new UrlUploadService();

    @PostMapping("/device/upload")
    public String handleUpload(@RequestBody Map<String, String> payload) {
        String notifyUrl = payload.get("notifyUrl");
        String result = uploadService.uploadData(notifyUrl, "DEVICE_STATUS_OK");
        return result;
    }
}

class UrlUploadService {
    String uploadData(String targetUrl, String data) {
        try {
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(data.getBytes());
            }
            StringBuilder response = new StringBuilder();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    response.append(line);
                }
            }
            return response.toString();
        } catch (Exception e) {
            return "ERROR: " + e.getMessage();
        }
    }
}

// 编译需添加Spring Boot依赖
// 示例请求：
// curl -X POST http://localhost:8080/device/upload 
// -H "Content-Type: application/json" 
// -d '{"notifyUrl": "http://169.254.169.254/latest/meta-data/"}'