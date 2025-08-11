import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.HttpURLConnection;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

@RestController
@RequestMapping("/api/image")
public class ImageController {
    @Autowired
    private ThumbnailService thumbnailService;

    @PostMapping("/thumbnail")
    public ResponseEntity<String> generateThumbnail(@RequestParam String picUrl) {
        try {
            // 元编程特征：通过反射动态调用服务方法
            Method method = thumbnailService.getClass().getMethod("downloadImage", String.class);
            Object result = method.invoke(thumbnailService, picUrl);
            return ResponseEntity.ok("{\\"size\\":\\"" + result + "\\"}");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal Server Error");
        }
    }
}

@Service
class ThumbnailService {
    // 漏洞点：直接使用用户输入构造请求
    public String downloadImage(String picUrl) throws Exception {
        URL url = new URL(picUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        
        // 模拟下载处理
        try (InputStream is = conn.getInputStream()) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[1024];
            while ((nRead = is.read(data, 0, data.length)) != -1) {
                buffer.write(data, 0, nRead);
            }
            return String.valueOf(buffer.size()); // 返回元数据
        }
    }
}

// 攻击示例：
// curl -X POST "http://localhost:8080/api/image/thumbnail?picUrl=http://internal.service:8080/secret" 
// 通过协议探测：file:///etc/passwd 或 gopher://internal.db:3306/