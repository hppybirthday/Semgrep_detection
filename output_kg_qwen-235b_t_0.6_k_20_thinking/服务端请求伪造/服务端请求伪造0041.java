package com.example.bigdata;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

@RestController
@RequestMapping("/data")
public class DataImportController {
    private static final Logger logger = Logger.getLogger(DataImportController.class.getName());

    // 模拟大数据处理接口：接收外部数据源URL并直接读取内容
    @GetMapping("/import")
    public String importData(@RequestParam("source") String dataSourceUrl) {
        StringBuilder result = new StringBuilder();
        BufferedReader reader = null;
        try {
            // 危险操作：直接使用用户输入构造URL对象
            URL url = new URL(dataSourceUrl);
            URLConnection connection = url.openConnection();
            
            // 强制设置超时时间（看似安全但无法防御SSRF）
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            
            // 存在漏洞的代码位置：未验证目标地址安全性
            reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8)
            );
            
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            
            logger.info("Successfully imported data from: " + dataSourceUrl);
            return "Imported data size: " + result.length() + " bytes";
            
        } catch (Exception e) {
            logger.severe("Data import failed: " + e.getMessage());
            return "Error importing data: " + e.getMessage();
            
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    logger.warning("Failed to close reader: " + e.getMessage());
                }
            }
        }
    }

    // 模拟内部敏感数据接口（用于演示SSRF危害）
    @GetMapping("/internal/secret")
    public String getSecretData() {
        return "INTERNAL_SECRET_DATA: This should never be exposed!";
    }
}