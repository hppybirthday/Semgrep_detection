package com.example.ssrf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;

@RestController
@RequestMapping("/api/v1")
public class DocumentProxyController {
    @Autowired
    private InternalDocumentService internalDocumentService;

    @GetMapping("/document")
    public ResponseEntity<String> getDocument(@RequestParam String url) throws URISyntaxException {
        // 高风险：直接使用用户提供的URL进行内部请求
        URI targetUri = new URI(url);
        String documentContent = internalDocumentService.fetchDocument(targetUri);
        return ResponseEntity.ok(documentContent);
    }
}

class InternalDocumentService {
    private final RestTemplate restTemplate;

    public InternalDocumentService() {
        this.restTemplate = new RestTemplate();
    }

    public String fetchDocument(URI documentUri) {
        // 模拟内部文档处理流程
        System.out.println("[审计日志] 正在访问文档资源: " + documentUri.toString());
        
        // 存在漏洞：未验证目标URI的合法性
        ResponseEntity<String> response = restTemplate.getForEntity(documentUri, String.class);
        
        // 模拟文档内容处理
        if (response.getStatusCode().is2xxSuccessful()) {
            return processDocumentContent(response.getBody());
        }
        return "文档访问失败: " + response.getStatusCodeValue();
    }

    private String processDocumentContent(String content) {
        // 模拟文档处理逻辑
        return "处理后的文档内容摘要: " + content.substring(0, Math.min(100, content.length())) + "...";
    }
}

// 配置类（模拟）
@Configuration
class ServiceConfig {
    @Bean
    public InternalDocumentService internalDocumentService() {
        return new InternalDocumentService();
    }
}

// 模拟的文档存储服务
@Service
class DocumentStorage {
    public String getInternalDocument(String docId) {
        // 实际应通过安全验证访问内部资源
        return "机密文档内容 - ID: " + docId;
    }
}

// 漏洞利用示例:
// curl "http://localhost:8080/api/v1/document?url=http://169.254.169.254/latest/meta-data/"
// curl "http://localhost:8080/api/v1/document?url=http://localhost:8080/admin/internal-api"