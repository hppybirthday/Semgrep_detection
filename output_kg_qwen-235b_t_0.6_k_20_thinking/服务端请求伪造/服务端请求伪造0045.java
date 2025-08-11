package com.example.ssrfdemo;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/simulate")
public class SimulationController {
    private final SimulationService simulationService = new SimulationService();

    @GetMapping("/data")
    public String simulateData(@RequestParam String url) {
        try {
            // 元编程特性：通过反射调用动态方法
            Method method = SimulationService.class.getMethod("execute", String.class);
            return (String) method.invoke(simulationService, url);
        } catch (Exception e) {
            return "Error in simulation: " + e.getMessage();
        }
    }

    @Service
    static class SimulationService {
        private final CloseableHttpClient httpClient = HttpClients.createDefault();

        public String execute(String targetUrl) throws IOException {
            // 存在漏洞的代码：直接使用用户输入的URL发起请求
            HttpGet request = new HttpGet(targetUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                // 返回原始响应内容
                return EntityUtils.toString(response.getEntity());
            }
        }

        // 模拟数据处理方法
        public Map<String, Object> processData(String rawData) {
            Map<String, Object> result = new HashMap<>();
            result.put("length", rawData.length());
            result.put("preview", rawData.substring(0, Math.min(100, rawData.length())));
            return result;
        }
    }

    // 全局异常处理器
    @ControllerAdvice
    static class SimulationExceptionAdvice {
        @ExceptionHandler(IOException.class)
        public String handleIOException(IOException e) {
            return "Network error: " + e.getMessage();
        }
    }
}