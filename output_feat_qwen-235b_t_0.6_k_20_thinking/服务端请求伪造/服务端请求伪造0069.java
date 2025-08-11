package com.example.ssrf.demo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/v1")
class FetchController {
    @Autowired
    private ExternalService externalService;

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchData(@RequestParam String data) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode jsonNode = mapper.readTree(data);
        
        List<String> paths = new ArrayList<>();
        jsonNode.get("p").forEach(node -> paths.add(node.asText()));
        
        // 取第三个元素构造路径
        String targetPath = paths.size() > 2 ? paths.get(2) : "default";
        
        String result = externalService.fetchExternalData(targetPath);
        return ResponseEntity.ok(result);
    }
}

@Service
class ExternalService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String fetchExternalData(String path) {
        // 漏洞点：直接拼接用户输入到URL中
        String url = "http://internal-api.example.com/data/" + path;
        
        // 模拟访问内部服务
        return restTemplate.getForObject(url, String.class);
    }
}

// 模拟攻击请求示例：
// /api/v1/fetch?data={"p":["a","b","../../169.254.169.254/latest/meta-data/instances"]}