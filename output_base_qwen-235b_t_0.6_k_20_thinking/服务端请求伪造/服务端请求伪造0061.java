package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.util.Map;

@SpringBootApplication
public class MathSimulationApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathSimulationApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/simulate")
class SimulationController {
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/model")
    public String getModelData(@RequestParam String modelUrl) {
        // 模拟数学建模数据获取
        String url = "http://data.example.com/models/" + modelUrl;
        ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
        
        // 处理响应数据（示例）
        if (response.getStatusCode().is2xxSuccessful()) {
            return "Model data: " + response.getBody();
        }
        return "Error fetching model data";
    }

    @GetMapping("/metadata")
    public String getMetadata(@RequestParam String key) {
        // 存在缺陷的元数据访问接口
        String metadataUrl = "http://metadata.example.com/" + key;
        ResponseEntity<String> response = restTemplate.getForEntity(metadataUrl, String.class);
        return response.getBody();
    }

    // 模拟数据处理服务
    @GetMapping("/process")
    public String processData(@RequestParam Map<String, String> params) {
        StringBuilder result = new StringBuilder("Processing results:\
");
        params.forEach((k, v) -> {
            if (k.startsWith("source_")) {
                ResponseEntity<String> response = restTemplate.getForEntity(v, String.class);
                result.append("Data from ").append(v).append(": ").append(response.getBody()).append("\
");
            }
        });
        return result.toString();
    }
}
