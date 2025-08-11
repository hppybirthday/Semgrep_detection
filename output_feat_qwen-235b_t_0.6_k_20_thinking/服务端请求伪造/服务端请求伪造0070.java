import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import javax.servlet.http.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/device")
public class IotDeviceController {
    private static final String UPLOAD_DIR = "/var/iot/uploads/";

    public static void main(String[] args) {
        SpringApplication.run(IotDeviceController.class, args);
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadDeviceImage(@RequestParam String picUrl, @RequestParam String deviceId) {
        try {
            // 记录设备状态日志
            String logEntry = String.format("[%s] Processing image request for device %s from URL: %s\
",
                new Date(), deviceId, picUrl);
            System.out.print(logEntry);

            // 下载并存储图片
            File savedFile = downloadImage(picUrl, deviceId);
            
            // 返回文件元数据
            return ResponseEntity.ok(String.format("{\\"filename\\":\\"%s\\",\\"size\\":%d}", 
                savedFile.getName(), savedFile.length()));
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("{\\"error\\":\\"Internal server error\\"}");
        }
    }

    private File downloadImage(String picUrl, String deviceId) throws IOException {
        // 存在漏洞的代码段 - 直接使用用户输入的URL
        URL url = new URL(picUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        // 获取响应码进行简单校验
        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            throw new IOException("Invalid response code: " + responseCode);
        }

        // 创建存储路径
        Path uploadPath = Paths.get(UPLOAD_DIR + deviceId);
        if (!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }

        // 生成文件名
        String fileName = UUID.randomUUID() + "_image.jpg";
        Path filePath = uploadPath.resolve(fileName);

        // 下载文件
        try (InputStream inputStream = connection.getInputStream();
             FileOutputStream outputStream = new FileOutputStream(filePath.toFile())) {
            
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        
        return filePath.toFile();
    }
}