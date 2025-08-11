package com.example.bigdata;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

// 接口定义
interface DataFetcher {
    String fetchData(String url) throws IOException;
}

// 大数据处理核心类
@Service
class ExternalDataFetcher implements DataFetcher {
    @Override
    public String fetchData(String url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            // 存在漏洞的代码：直接使用用户输入的URL
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
}

// 数据处理服务
@Service
class DataProcessor {
    private final DataFetcher dataFetcher;

    public DataProcessor(DataFetcher dataFetcher) {
        this.dataFetcher = dataFetcher;
    }

    public String processExternalData(String dataSourceUrl) throws IOException {
        // 获取外部数据
        String rawData = dataFetcher.fetchData(dataSourceUrl);
        // 模拟数据处理
        return "Processed data length: " + rawData.length();
    }
}

// 模拟控制器
@RestController
class DataController {
    private final DataProcessor dataProcessor;

    public DataController(DataProcessor dataProcessor) {
        this.dataProcessor = dataProcessor;
    }

    @GetMapping("/process")
    public String handleDataProcessing(@RequestParam String url) throws IOException {
        // 直接将用户输入的URL传递给数据处理层
        return dataProcessor.processExternalData(url);
    }
}

// 主应用类
@SpringBootApplication
public class BigDataServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(BigDataServiceApplication.class, args);
    }
}