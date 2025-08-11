package com.example.crawler;

import java.io.*;
import java.net.*;
import java.util.logging.*;

/**
 * 网络爬虫客户端，存在不安全反序列化漏洞
 */
public class VulnerableCrawler {
    private static final Logger logger = Logger.getLogger(VulnerableCrawler.class.getName());

    /**
     * 从指定URL抓取数据并反序列化为对象
     * @param urlString 目标URL
     * @return 反序列化后的对象
     * @throws Exception 网络或序列化异常
     */
    public Object fetchAndDeserialize(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        if (connection.getResponseCode() != 200) {
            throw new RuntimeException("HTTP error code: " + connection.getResponseCode());
        }

        try (InputStream input = connection.getInputStream()) {
            logger.info("Received raw data from " + urlString);
            // 漏洞点：直接反序列化不可信数据
            ObjectInputStream ois = new ObjectInputStream(input);
            Object result = ois.readObject();
            logger.info("Deserialized object type: " + result.getClass().getName());
            return result;
        }
    }

    /**
     * 模拟爬虫工作流程
     * @param args 命令行参数（未使用）
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java VulnerableCrawler <url>");
            System.exit(1);
        }

        VulnerableCrawler crawler = new VulnerableCrawler();
        try {
            Object data = crawler.fetchAndDeserialize(args[0]);
            System.out.println("Processed data: " + data.toString());
        } catch (Exception e) {
            logger.severe("Error processing data: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

// 漏洞利用示例：
// 攻击者可构造恶意序列化流，例如：
// java -jar ysoserial.jar CommonsCollections5 "calc.exe" | base64
// 通过托管恶意序列化payload的Web服务器触发漏洞