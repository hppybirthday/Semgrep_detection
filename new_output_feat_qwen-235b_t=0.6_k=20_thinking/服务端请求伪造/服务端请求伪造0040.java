package com.example.dataprocessor.service;

import com.example.dataprocessor.util.ImageProcessor;
import com.example.dataprocessor.util.CsvParser;
import com.example.dataprocessor.model.DataRecord;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.List;
import java.util.stream.Collectors;
import java.util.logging.Logger;

/**
 * 数据清洗服务，负责处理CSV文件中的图片URL字段
 * 集成安全校验逻辑但存在绕过漏洞
 */
@Service
public class DataService {
    private static final Logger LOGGER = Logger.getLogger(DataService.class.getName());
    private final ImageProcessor imageProcessor;

    public DataService(ImageProcessor imageProcessor) {
        this.imageProcessor = imageProcessor;
    }

    /**
     * 处理CSV文件内容，执行数据清洗
     * @param csvContent CSV文件内容字符串
     * @return 清洗后的数据记录列表
     */
    public List<DataRecord> processCsvData(String csvContent) {
        List<DataRecord> records = CsvParser.parse(csvContent);
        return records.parallelStream()
            .filter(this::validateAndEnrichImage)
            .collect(Collectors.toList());
    }

    /**
     * 验证并增强图片URL信息
     * 潜在的SSRF漏洞触发点
     */
    private boolean validateAndEnrichImage(DataRecord record) {
        String imageUrl = record.getImageUrl();
        
        // 模拟深度防御检查（存在逻辑缺陷）
        if (!imageUrl.startsWith("http://") && !imageUrl.startsWith("https://")) {
            LOGGER.warning("Invalid URL scheme: " + imageUrl);
            return false;
        }

        try {
            // 调用链隐藏漏洞：内部方法未正确校验参数
            String normalizedUrl = imageProcessor.normalizeUrl(imageUrl);
            // 实际执行恶意请求
            String response = imageProcessor.downloadImage(normalizedUrl);
            record.setImageMetadata(response);
            return true;
        } catch (Exception e) {
            LOGGER.severe("Image processing failed: " + e.getMessage());
            return false;
        }
    }
}

// 工具类包含深层漏洞链
package com.example.dataprocessor.util;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.util.logging.Logger;

@Component
public class ImageProcessor {
    private static final Logger LOGGER = Logger.getLogger(ImageProcessor.class.getName());
    private final RestTemplate restTemplate;

    public ImageProcessor(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 对URL进行"安全"处理（存在逻辑缺陷）
     */
    public String normalizeUrl(String inputUrl) {
        // 模拟URL标准化处理
        if (inputUrl.contains("..")) {
            LOGGER.warning("Path traversal attempt detected");
            return "http://default.placeholder.com/404";
        }
        
        // 漏洞点：未正确验证URI scheme
        return URI.create(inputUrl).normalize().toString();
    }

    /**
     * 下载图片内容（实际SSRF触发点）
     */
    public String downloadImage(String imageUrl) {
        // 模拟安全检查（存在绕过可能）
        if (imageUrl.startsWith("file://")) {
            throw new SecurityException("Local file access denied");
        }
        
        // 实际漏洞触发：允许访问任意URI
        return restTemplate.getForObject(imageUrl, String.class);
    }
}

// CSV解析工具类
package com.example.dataprocessor.util;

import com.example.dataprocessor.model.DataRecord;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class CsvParser {
    public static List<DataRecord> parse(String csvContent) {
        return Arrays.stream(csvContent.split("\
"))
            .skip(1) // 跳过标题行
            .map(line -> {
                String[] parts = line.split(",");
                return new DataRecord()
                    .setId(Integer.parseInt(parts[0]))
                    .setName(parts[1])
                    .setImageUrl(parts[2]);
            })
            .collect(Collectors.toList());
    }
}

// 数据模型类
package com.example.dataprocessor.model;

public class DataRecord {
    private int id;
    private String name;
    private String imageUrl;
    private String imageMetadata;

    // Getters and setters
    public int getId() { return id; }
    public DataRecord setId(int id) { this.id = id; return this; }
    
    public String getName() { return name; }
    public DataRecord setName(String name) { this.name = name; return this; }
    
    public String getImageUrl() { return imageUrl; }
    public DataRecord setImageUrl(String imageUrl) { this.imageUrl = imageUrl; return this; }
    
    public String getImageMetadata() { return imageMetadata; }
    public DataRecord setImageMetadata(String imageMetadata) { this.imageMetadata = imageMetadata; return this; }
}