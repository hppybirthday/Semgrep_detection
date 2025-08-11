package com.example.vulnerableapp;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class AttachmentService {
    // 模拟防御式编程中的错误假设：认为URL参数已通过前端验证
    public String uploadFromUrl(String urlParam) {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        try {
            // 漏洞点：直接使用用户输入构造URI
            URI uri = new URI(urlParam);
            HttpGet request = new HttpGet(uri);
            
            // 模拟文件下载处理
            CloseableHttpResponse response = httpClient.execute(request);
            HttpEntity entity = response.getEntity();
            
            if (entity != null) {
                // 漏洞危害体现：读取任意响应内容
                String content = EntityUtils.toString(entity);
                
                // 存储响应内容（可能包含敏感数据）
                Path tempFile = Files.createTempFile("attachment_", ".tmp");
                try (FileOutputStream fos = new FileOutputStream(tempFile.toFile())) {
                    fos.write(content.getBytes());
                }
                
                return "File saved to: " + tempFile.toString();
            }
            
        } catch (Exception e) {
            // 错误的安全处理：仅记录日志但未阻断攻击
            System.err.println("Download failed: " + e.getMessage());
            return "Download failed";
        } finally {
            try {
                httpClient.close();
            } catch (IOException e) {
                // 忽略关闭异常
            }
        }
        return "Empty response";
    }
}

// 控制器层示例（漏洞触发点）
@RestController
@RequestMapping("/attachments")
public class AttachmentController {
    @Autowired
    private AttachmentService attachmentService;
    
    @GetMapping("/download")
    public String handleDownload(@RequestParam("url") String url) {
        // 错误的安全验证：仅检查非空但未验证内容
        if (url == null || url.isEmpty()) {
            return "URL parameter is required";
        }
        
        // 危险的业务逻辑调用
        return attachmentService.uploadFromUrl(url);
    }
}