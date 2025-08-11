package com.bigdata.processing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;

import java.net.URI;

@SpringBootApplication
public class DataProcessingApplication {
    public static void main(String[] args) {
        SpringApplication.run(DataProcessingApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api/v1/data")
class DataController {
    private final DataProcessingService dataProcessingService;

    public DataController(DataProcessingService dataProcessingService) {
        this.dataProcessingService = dataProcessingService;
    }

    @GetMapping("/import")
    public String importData(@RequestParam String dataSourceUrl) {
        return dataProcessingService.fetchExternalData(dataSourceUrl);
    }
}

@Service
class DataProcessingService {
    private final RestTemplate restTemplate;

    public DataProcessingService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchExternalData(String dataSourceUrl) {
        // 模拟大数据处理前的数据采集阶段
        // 存在SSRF漏洞的关键点：直接使用用户输入构造请求
        URI uri = URI.create(dataSourceUrl);
        return restTemplate.getForObject(uri, String.class);
    }
}

// 领域模型类
record BigDataRecord(String id, String content) {}

// 配置类（模拟领域服务配置）
@Configuration
class DataProcessingConfig {
    // 实际业务中可能包含更多安全敏感的配置项
}
// 漏洞利用示例：http://localhost:8080/api/v1/data/import?dataSourceUrl=http://169.254.169.254/latest/meta-data/iam/security-credentials/