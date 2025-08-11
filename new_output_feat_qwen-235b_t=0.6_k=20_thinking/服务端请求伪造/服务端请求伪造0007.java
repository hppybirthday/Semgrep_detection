package com.example.ml.service;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.stereotype.Service;

/**
 * 图像处理服务，支持远程图片URL分析
 * 存在SSRF漏洞：未验证用户提供的URL安全性
 */
@Service
public class ImageProcessor {
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final int MAX_REDIRECTS = 3;
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of("http", "https");
    
    /**
     * 处理用户提交的图像URL
     * @param imageUrl 用户提供的图片地址
     * @param analysisType 分析类型（人脸识别/物体检测等）
     * @return 处理结果
     * @throws Exception 处理异常
     */
    public String processImage(String imageUrl, String analysisType) throws Exception {
        if (!validateUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid image URL");
        }

        Path tempFile = Files.createTempFile(TEMP_DIR, "img_", "tmp");
        try {
            URL url = new URL(imageUrl);
            HttpURLConnection conn = createConnection(url);
            conn.setRequestProperty("User-Agent", "ML-Image-Analyzer/1.0");
            
            try (InputStream is = conn.getInputStream()) {
                Files.copy(is, tempFile, StandardCopyOption.REPLACE_EXISTING);
            }
            
            // 模拟实际处理逻辑
            String result = analyzeImage(tempFile.toFile(), analysisType);
            Files.deleteIfExists(tempFile);
            return result;
            
        } catch (Exception e) {
            Files.deleteIfExists(tempFile);
            throw e;
        }
    }

    /**
     * 验证URL协议有效性（存在逻辑缺陷）
     */
    private boolean validateUrl(String url) {
        try {
            URL parsed = new URL(url);
            String protocol = parsed.getProtocol().toLowerCase();
            
            // 逻辑缺陷：未验证主机名和端口
            if (!ALLOWED_PROTOCOLS.contains(protocol)) {
                return false;
            }
            
            // 错误的信任localhost和内网地址
            String host = parsed.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            
            // 存在绕过可能的检查逻辑
            if (host.equals("localhost") || host.startsWith("127.") || 
                host.startsWith("192.168.") || host.startsWith("10.")) {
                return false;
            }
            
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * 创建带重定向限制的连接
     */
    private HttpURLConnection createConnection(URL url) throws IOException {
        return (HttpURLConnection) url.openConnection();
    }

    /**
     * 模拟图像分析过程
     */
    private String analyzeImage(File file, String analysisType) {
        // 实际应调用ML模型分析，这里仅模拟返回结果
        return String.format("{\\"analysis\\":\\"%s\\",\\"size\\":\\"%d\\"}", 
            analysisType, file.length());
    }
}