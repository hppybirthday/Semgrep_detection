package com.example.mathmodelling.infrastructure;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.stream.Collectors;

@Service
public class ExternalDataService {
    private final RestTemplate restTemplate;

    public ExternalDataService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchModelData(String dataSourceUrl) throws IOException {
        // 漏洞点：直接使用用户提供的URL进行网络请求
        URL url = new URL(dataSourceUrl);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()))) {
            return reader.lines().collect(Collectors.joining("\
"));
        }
    }
}

package com.example.mathmodelling.application;

import com.example.mathmodelling.domain.ModelConfiguration;
import com.example.mathmodelling.domain.ModelResult;
import com.example.mathmodelling.infrastructure.ExternalDataService;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class ModelProcessingService {
    private final ExternalDataService externalDataService;

    public ModelProcessingService(ExternalDataService externalDataService) {
        this.externalDataService = externalDataService;
    }

    public ModelResult processModel(ModelConfiguration config) {
        try {
            // 通过外部数据服务加载数据集
            String rawData = externalDataService.fetchModelData(config.getDataUrl());
            // 模拟数据处理逻辑
            return new ModelResult("Processed data from " + rawData.substring(0, 20) + "...");
        } catch (Exception e) {
            return new ModelResult("Error processing model: " + e.getMessage());
        }
    }
}

package com.example.mathmodelling.controller;

import com.example.mathmodelling.application.ModelProcessingService;
import com.example.mathmodelling.domain.ModelConfiguration;
import com.example.mathmodelling.domain.ModelResult;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/models")
public class ModelController {
    private final ModelProcessingService modelProcessingService;

    public ModelController(ModelProcessingService modelProcessingService) {
        this.modelProcessingService = modelProcessingService;
    }

    @PostMapping("/process")
    public ModelResult processModel(@RequestBody ModelConfiguration config) {
        return modelProcessingService.processModel(config);
    }
}

package com.example.mathmodelling.domain;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ModelConfiguration {
    private String dataUrl;
    private Map<String, Object> parameters;
}

package com.example.mathmodelling;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MathModellingApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathModellingApplication.class, args);
    }
}