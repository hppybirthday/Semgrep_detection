import java.io.*;
import java.net.*;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class DataCleaner {
    @PostMapping("/clean")
    @ResponseBody
    public String cleanData(@RequestParam("file") MultipartFile file) {
        try {
            List<String> lines = new BufferedReader(
                new InputStreamReader(file.getInputStream()))
                .lines().collect(Collectors.toList());

            List<String> cleanedData = new ArrayList<>();
            for (String line : lines) {
                String[] parts = line.split(",");
                if (parts.length >= 2) {
                    String url = parts[0].trim();
                    String value = parts[1].trim();
                    
                    // 危险的URL处理逻辑
                    if (isValidURL(url)) {
                        String content = fetchURLContent(url);
                        cleanedData.add(content + "," + value);
                    }
                }
            }

            return "Cleaned data size: " + cleanedData.size();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private boolean isValidURL(String url) {
        try {
            URI uri = new URI(url);
            String scheme = uri.getScheme().toLowerCase();
            // 错误的协议白名单检查
            return scheme.equals("http") || scheme.equals("https");
        } catch (URISyntaxException e) {
            return false;
        }
    }

    private String fetchURLContent(String urlString) throws IOException {
        try {
            URL url = new URL(urlString);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            
            // 危险的自动重定向处理
            conn.setInstanceFollowRedirects(true);
            
            if (conn.getResponseCode() == 200) {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
                return reader.lines().collect(Collectors.joining("\
"));
            }
            return "";
        } catch (Exception e) {
            throw new IOException("URL fetch failed: " + e.getMessage());
        }
    }
}