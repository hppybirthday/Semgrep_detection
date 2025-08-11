package com.example.bigdata;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

// 高抽象建模风格：抽象数据源基类
abstract class AbstractDataSource {
    public abstract String fetchData() throws IOException;
}

// 具体HTTP数据源实现
class HttpDataSource extends AbstractDataSource {
    private final String url;

    public HttpDataSource(String url) {
        this.url = url;
    }

    @Override
    public String fetchData() throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
}

// 大数据处理服务
@Controller
public class DataProcessor {
    // 模拟大数据处理接口
    @GetMapping("/process")
    @ResponseBody
    public String process(@RequestParam("source") String dataSourceUrl) {
        try {
            // 直接使用用户输入作为数据源地址（漏洞点）
            AbstractDataSource source = new HttpDataSource(dataSourceUrl);
            String rawData = source.fetchData();
            // 模拟数据处理逻辑
            return "Data length: " + rawData.length();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟内部监控接口（攻击目标）
    @GetMapping("/internal/metrics")
    @ResponseBody
    private String getInternalMetrics() {
        return "{\\"cpu\\":\\"85%\\",\\"secret\\":\\"INTERNAL_DATA\\"}";
    }
}