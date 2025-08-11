package com.example.bigdata.processor;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;

/**
 * 抽象大数据处理器，定义处理模板
 */
public abstract class AbstractDataProcessor {
    public abstract String fetchData(String sourceUrl);
    public abstract void processData(String rawData);
    
    public final void executeProcessing(String sourceUrl) {
        String rawData = fetchData(sourceUrl);
        if (rawData != null && !rawData.isEmpty()) {
            processData(rawData);
        }
    }
}

/**
 * 远程数据获取实现类
 */
@Service
class RemoteDataFetcher extends AbstractDataProcessor {
    @Override
    public String fetchData(String sourceUrl) {
        return HttpClientUtil.executeGet(sourceUrl);
    }

    @Override
    public void processData(String rawData) {
        // 模拟数据处理逻辑
        System.out.println("Processing data length: " + rawData.length());
    }
}

/**
 * HTTP请求工具类（存在SSRF漏洞）
 */
class HttpClientUtil {
    public static String executeGet(String url) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(client.execute(request).getEntity());
        } catch (IOException e) {
            e.printStackTrace();
            return "Error fetching data";
        }
    }
}

/**
 * 数据处理服务入口
 */
@Service
class DataProcessingService {
    private final AbstractDataProcessor dataProcessor;

    public DataProcessingService(AbstractDataProcessor dataProcessor) {
        this.dataProcessor = dataProcessor;
    }

    public void handleUserRequest(String sourceUrl) {
        System.out.println("Received request for URL: " + sourceUrl);
        dataProcessor.executeProcessing(sourceUrl);
    }
}

// 模拟Spring配置类
@Configuration
class AppConfig {
    @Bean
    public AbstractDataProcessor remoteDataFetcher() {
        return new RemoteDataFetcher();
    }

    @Bean
    public DataProcessingService dataProcessingService() {
        return new DataProcessingService(remoteDataFetcher());
    }
}