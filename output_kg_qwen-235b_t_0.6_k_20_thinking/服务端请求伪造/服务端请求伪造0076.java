package com.example.mathmodel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.io.IOException;
import java.util.Objects;

// 数学模型聚合根
public class MathModel {
    private String name;
    private String description;
    
    public MathModel(String name, String description) {
        this.name = name;
        this.description = description;
    }
    
    // 模型仿真服务类（领域服务）
    public static class SimulatorService {
        private final HttpClient httpClient = HttpClient.newHttpClient();
        
        /**
         * 从外部URL获取数据进行仿真
         * @param dataUrl 用户提供的数据源URL
         * @return 处理后的仿真结果
         * @throws IOException
         * @throws InterruptedException
         */
        public String simulateFromExternalData(String dataUrl) throws IOException, InterruptedException {
            // 漏洞点：直接使用用户输入的URL发起请求
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(dataUrl))
                .header("Content-Type", "application/json")
                .GET()
                .build();
            
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            
            // 处理响应数据（示例逻辑）
            if (response.statusCode() == 200) {
                return processSimulationData(response.body());
            }
            return "Simulation failed with status: " + response.statusCode();
        }
        
        private String processSimulationData(String rawData) {
            // 简单的处理逻辑示例
            return "Processed simulation result: " + rawData.hashCode();
        }
    }
    
    // 模型仓储接口（简化版）
    public interface ModelRepository {
        MathModel findById(String id);
        void save(MathModel model);
    }
    
    // 应用主类
    public static class SimulatorApplication {
        public static void main(String[] args) {
            try {
                SimulatorService simulator = new SimulatorService();
                // 模拟用户输入（攻击示例）
                String userInputUrl = "http://localhost:8080/internal-api/secret-data";
                String result = simulator.simulateFromExternalData(userInputUrl);
                System.out.println("Simulation Result: " + result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}