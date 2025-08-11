package com.example.ml;

import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@RestController
@RequestMapping("/api/ml")
public class ModelTrainer {
    
    @PostMapping("/train")
    public String trainModel(@RequestBody DatasetRequest request) {
        String datasetUrl = request.getUrl();
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet httpGet = new HttpGet(datasetUrl);
            return client.execute(httpGet, response -> {
                if (response.getStatusLine().getStatusCode() == 200) {
                    return EntityUtils.toString(response.getEntity());
                }
                return "Error fetching dataset";
            });
        } catch (IOException e) {
            e.printStackTrace();
            return "Error: " + e.getMessage();
        }
    }

    static class DatasetRequest {
        private String url;
        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
    }

    // 模拟训练逻辑
    private void processDataset(String data) {
        // 实际处理数据集的代码
        System.out.println("Processing dataset with length: " + data.length());
    }
}

/*
漏洞示例请求：
POST /api/ml/train HTTP/1.1
Content-Type: application/json

{"url":"file:///etc/passwd"}

攻击面：
1. 本地文件读取：使用file://协议访问敏感文件
2. 内部服务探测：访问http://localhost:8080/admin等内部接口
3. 外部服务攻击：通过DNS重绑定绕过IP限制
4. SSRF-to-XXE组合攻击：通过协议处理器漏洞
*/