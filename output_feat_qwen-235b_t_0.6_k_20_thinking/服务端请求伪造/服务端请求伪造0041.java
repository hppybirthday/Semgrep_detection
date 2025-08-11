package com.example.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @RestController
    public static class DataProcessorController {
        @PostMapping("/process")
        public ResponseEntity<String> processData(@RequestBody Map<String, Object> payload, HttpServletResponse response) throws IOException {
            // 声明式配置的JSON数据解析
            Object[] dataArray = (Object[]) payload.get("data");
            
            // 危险的数据提取逻辑（SSRF触发点）
            String targetUrl = extractUrlFromPayload(dataArray);
            
            // 服务端直接发起外部请求（未验证目标主机）
            URL url = new URL(targetUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            
            // 模拟大数据下载处理
            String localPath = "/tmp/processed_data.bin";
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                 FileOutputStream writer = new FileOutputStream(localPath)) {
                
                char[] buffer = new char[8192];
                int bytesRead;
                while ((bytesRead = reader.read(buffer)) > 0) {
                    writer.write(buffer, 0, bytesRead);
                }
            }
            
            // 响应仅返回元数据（隐藏实际访问行为）
            response.setHeader("X-File-Size", String.valueOf(new java.io.File(localPath).length()));
            return ResponseEntity.ok().build();
        }

        private String extractUrlFromPayload(Object[] data) {
            // 污染点：从JSON数组多层嵌套结构中提取URL
            if (data != null && data.length > 2) {
                Object thirdElement = data[2];
                if (thirdElement instanceof Map) {
                    // 支持多字段污染路径（b/p数组的第三个元素）
                    Map<?, ?> nestedMap = (Map<?, ?>) thirdElement;
                    if (nestedMap.containsKey("b")) {
                        Object[] bArray = (Object[]) nestedMap.get("b");
                        if (bArray.length > 2) {
                            return bArray[2].toString();
                        }
                    }
                    if (nestedMap.containsKey("p")) {
                        Object[] pArray = (Object[]) nestedMap.get("p");
                        if (pArray.length > 2) {
                            return pArray[2].toString();
                        }
                    }
                }
            }
            return "https://default-source.example.com/datafeed";
        }
    }
}