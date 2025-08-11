package com.example.bigdata.infrastructure.datasource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.logging.Logger;

/**
 * 模拟存在SSRF漏洞的HTTP客户端工具类
 * 用于演示大数据处理场景中的数据源配置加载
 */
public class VulnerableHttpClient {
    private static final Logger logger = Logger.getLogger("VulnerableHttpClient");

    public String fetchDataFromExternalSource(String dataSourceUrl) throws IOException {
        StringBuilder response = new StringBuilder();
        
        // 漏洞点：直接使用用户提供的URL参数
        URL url = new URL(dataSourceUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        connection.setRequestMethod("GET");
        
        int responseCode = connection.getResponseCode();
        logger.info("Sending GET request to URL: " + dataSourceUrl);
        logger.info("Response Code: " + responseCode);
        
        BufferedReader in = new BufferedReader(
            new InputStreamReader(connection.getInputStream()));
        String inputLine;
        
        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        return response.toString();
    }
}

package com.example.bigdata.domain.datasource;

import com.example.bigdata.infrastructure.datasource.VulnerableHttpClient;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 数据源配置领域模型
 * 包含大数据处理所需的数据源元信息
 */
public class DataSourceConfig {
    private static final Logger logger = Logger.getLogger("DataSourceConfig");
    private String url;
    private String description;
    private Map<String, String> metadata;

    public DataSourceConfig(String url, String description, Map<String, String> metadata) {
        this.url = url;
        this.description = description;
        this.metadata = metadata;
    }

    // 漏洞点：领域服务直接调用存在漏洞的HTTP客户端
    public String loadData() {
        try {
            VulnerableHttpClient client = new VulnerableHttpClient();
            String result = client.fetchDataFromExternalSource(url);
            logger.info("Data loaded successfully from: " + url);
            return result;
        } catch (Exception e) {
            logger.severe("Failed to load data: " + e.getMessage());
            return "Error loading data";
        }
    }

    // Getters
    public String getUrl() { return url; }
    public String getDescription() { return description; }
    public Map<String, String> getMetadata() { return metadata; }
}

package com.example.bigdata.application;

import com.example.bigdata.domain.datasource.DataSourceConfig;
import org.springframework.stereotype.Service;
import java.util.Map;

/**
 * 数据导入应用服务
 * 处理大数据处理场景中的外部数据源加载业务逻辑
 */
@Service
public class DataImportService {
    // 漏洞点：应用层直接传递用户输入到领域模型
    public String importData(String dataSourceUrl, String description, Map<String, String> metadata) {
        DataSourceConfig config = new DataSourceConfig(dataSourceUrl, description, metadata);
        return config.loadData();
    }
}

package com.example.bigdata.api;

import com.example.bigdata.application.DataImportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 数据导入REST API
 * 暴露大数据处理服务的外部接口
 */
@RestController
@RequestMapping("/api/data/import")
public class DataImportController {
    @Autowired
    private DataImportService dataImportService;

    @PostMapping
    public String handleDataImport(@RequestParam String dataSourceUrl, 
                                  @RequestParam String description,
                                  @RequestBody Map<String, String> metadata) {
        // 漏洞点：直接将用户输入传递到业务逻辑
        return dataImportService.importData(dataSourceUrl, description, metadata);
    }
}