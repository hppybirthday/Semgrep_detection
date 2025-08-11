package com.example.crawler.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.URL;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 网络爬虫核心处理器
 * 高抽象建模风格实现
 */
public class CrawlerService {
    
    private final Map<String, DataProcessor> processorRegistry = new ConcurrentHashMap<>();
    
    public CrawlerService() {
        registerProcessor("serialized", new SerializedDataProcessor());
    }
    
    public void registerProcessor(String type, DataProcessor processor) {
        processorRegistry.put(type, processor);
    }
    
    public Object crawlAndProcess(String url, String processorType) throws Exception {
        // 模拟网络请求获取数据
        byte[] rawData = fetchDataFromUrl(url);
        
        DataProcessor processor = processorRegistry.get(processorType);
        if (processor == null) {
            throw new IllegalArgumentException("Unsupported processor type: " + processorType);
        }
        
        return processor.process(rawData);
    }
    
    private byte[] fetchDataFromUrl(String url) throws IOException {
        // 实际应使用网络请求库实现
        // 这里模拟返回恶意序列化数据
        if (url.contains("malicious")) {
            return generateMaliciousPayload();
        }
        return new byte[0];
    }
    
    private byte[] generateMaliciousPayload() {
        // 实际攻击中会通过工具生成gadget链
        // 此处模拟base64编码的恶意序列化数据
        return Base64.getDecoder().decode("rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eLdJQmFhoGgCABB4cHwwAA==");
    }
    
    public interface DataProcessor {
        Object process(byte[] data) throws Exception;
    }
    
    /**
     * 不安全的序列化数据处理器
     * 存在反序列化漏洞的关键组件
     */
    public static class SerializedDataProcessor implements DataProcessor {
        @Override
        public Object process(byte[] data) throws Exception {
            // 漏洞点：未经验证直接反序列化不可信数据
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                return ois.readObject();
            }
        }
    }
    
    // 模拟业务数据模型
    public static class CrawlerResponse implements Serializable {
        private static final long serialVersionUID = 1L;
        private String content;
        private int statusCode;
        
        // Getters/Setters
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
        public int getStatusCode() { return statusCode; }
        public void setStatusCode(int statusCode) { this.statusCode = statusCode; }
    }
    
    public static void main(String[] args) {
        try {
            CrawlerService service = new CrawlerService();
            // 模拟触发漏洞的调用
            service.crawlAndProcess("http://example.com/malicious", "serialized");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}