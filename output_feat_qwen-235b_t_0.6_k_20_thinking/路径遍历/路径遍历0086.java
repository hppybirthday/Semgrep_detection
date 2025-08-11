import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.util.FileCopyUtils;

@RestController
@RequestMapping("/api/v1/device")
public class DeviceDataController {
    
    private static final String UPLOAD_PATH = "/var/data/iot/uploads";
    
    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestParam("bizPath") String bizPath,
                                                  @RequestParam("file") MultipartFile file) {
        try {
            // 漏洞点：直接拼接用户输入路径
            File uploadDir = new File(UPLOAD_PATH + File.separator + bizPath);
            
            if (!uploadDir.exists()) {
                uploadDir.mkdirs();
            }
            
            // 生成安全文件名
            String originalFilename = file.getOriginalFilename();
            String safeFilename = UUID.randomUUID() + "_" + originalFilename;
            
            // 构造目标文件
            File destFile = new File(uploadDir, safeFilename);
            
            // 文件写入（漏洞触发点）
            FileCopyUtils.copy(file.getBytes(), destFile);
            
            // 模拟设备数据处理
            processDeviceData(destFile);
            
            return ResponseEntity.ok("File uploaded successfully");
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }
    
    private void processDeviceData(File dataFile) throws IOException {
        // 模拟设备数据处理逻辑
        Path tempPath = Files.createTempFile("device_", ".tmp");
        
        // 漏洞利用示例：攻击者可通过../路径删除任意文件
        if (dataFile.exists()) {
            Files.delete(dataFile); // 潜在危险操作
        }
        
        // 模拟数据解析
        Files.write(tempPath, "Processed device data".getBytes());
    }
}