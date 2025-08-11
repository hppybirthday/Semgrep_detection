package com.example.ml.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.function.Function;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainingController {

    private final WebClient webClient = WebClient.create();

    @PostMapping("/train")
    public Mono<String> trainModel(@RequestParam String datasetUrl) {
        return downloadDataset(datasetUrl)
            .flatMap(data -> processAndTrain(data))
            .map(result -> "Model trained successfully: " + result);
    }

    private Mono<String> downloadDataset(String url) {
        return webClient.get()
            .uri(url)
            .retrieve()
            .bodyToMono(String.class)
            .onErrorResume(ex -> Mono.just("Failed to download dataset: " + ex.getMessage()));
    }

    private Mono<String> processAndTrain(String data) {
        return Mono.just(data)
            .map(d -> d.length() > 100 ? "Model accuracy: 98.7%" : "Insufficient data");
    }

    // 模拟的特征工程函数
    Function<String, String> featureEngineering = data -> {
        if (data.contains("error")) {
            throw new IllegalArgumentException("Invalid data format");
        }
        return data.replaceAll("[^0-9.,]", "");
    };

    // 模拟的模型评估函数
    Function<String, Double> modelEvaluation = processedData -> {
        int rowCount = processedData.split("\
").length;
        return rowCount > 100 ? 0.92 : 0.65;
    };

    // 模拟的模型部署函数
    Function<String, String> deployModel = modelId -> String.format("Model %s deployed at /models/%s", modelId, modelId);

    // 完整的训练流水线
    @GetMapping("/pipeline")
    public Mono<String> trainingPipeline(@RequestParam String datasetUrl) {
        return downloadDataset(datasetUrl)
            .map(featureEngineering)
            .map(modelEvaluation)
            .map(acc -> String.format("Model accuracy: %.2f%%", acc * 100))
            .onErrorResume(ex -> Mono.just("Pipeline failed: " + ex.getMessage()));
    }

    // 用于演示SSRF漏洞的测试端点
    @GetMapping("/internal")
    public String internalEndpoint() {
        return "Internal API: Sensitive system metrics";
    }
}