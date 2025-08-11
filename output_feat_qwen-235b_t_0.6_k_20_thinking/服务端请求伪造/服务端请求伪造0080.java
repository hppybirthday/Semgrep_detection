import java.io.*;
import java.net.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/encrypt")
public class FileEncryptor {
    @GetMapping
    public void processFile(@RequestParam String fileUrl, HttpServletResponse response) throws Exception {
        // 模拟文件加密流程
        String encryptedData = encryptFile(fetchRemoteFile(fileUrl));
        response.getWriter().write("Encrypted: " + encryptedData);
    }

    private String fetchRemoteFile(String fileUrl) throws Exception {
        // 存在漏洞的代码：直接拼接用户输入构造URL
        URL url = new URL(fileUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        // 读取响应内容
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(conn.getInputStream()));
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        return result.toString();
    }

    private String encryptFile(String content) {
        // 简单模拟加密过程
        return Base64.getEncoder().encodeToString(content.getBytes());
    }
}

@Service
class ThumbnailService {
    public String generateThumbnail(String imageUrl) {
        try {
            // 二次漏洞触发点：内部服务调用
            URL url = new URL("http://image-processor/resize?url=" + imageUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            // 忽略响应处理...
            return "thumbnail_" + imageUrl.hashCode();
        } catch (Exception e) {
            return "ERROR";
        }
    }
}