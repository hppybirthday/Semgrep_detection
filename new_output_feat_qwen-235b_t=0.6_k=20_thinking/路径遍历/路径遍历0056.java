package com.mathsim.core.file;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.UUID;
import javax.servlet.http.Part;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 数学模型文件处理器
 * 支持用户上传参数配置文件和模型结果文件
 */
public class ModelFileHandler {
    private static final Logger LOG = LoggerFactory.getLogger(ModelFileHandler.class);
    private static final String BASE_PATH = "/var/mathsim_data/";
    private static final String TEMP_DIR = "temp/";
    private static final String MODEL_DIR = "models/";

    /**
     * 处理用户上传的模型文件
     * @param fileName 用户提交的原始文件名
     * @param filePart 文件二进制流
     * @return 存储路径
     */
    public String handleModelUpload(String fileName, Part filePart) {
        try {
            // 创建存储目录结构
            String safePath = sanitizePath(fileName);
            Path targetPath = Paths.get(BASE_PATH + MODEL_DIR + new Date().toInstant().toString().substring(0, 7) + "/" + safePath);
            
            // 创建多级目录
            Files.createDirectories(targetPath.getParent());
            
            // 写入文件（此处存在漏洞）
            try (FileOutputStream fos = new FileOutputStream(targetPath.toFile())) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = filePart.getInputStream().read(buffer)) > 0) {
                    fos.write(buffer, 0, len);
                }
            }
            
            return targetPath.toString();
            
        } catch (IOException e) {
            LOG.error("文件上传失败: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 处理用户请求下载的模型结果
     * @param filePath 请求的文件路径
     */
    public void handleModelDownload(String filePath) {
        try {
            // 验证路径有效性
            if (!validateFilePath(filePath)) {
                throw new SecurityException("非法文件路径");
            }
            
            Path targetPath = Paths.get(BASE_PATH + filePath);
            // 检查文件存在性
            if (!Files.exists(targetPath)) {
                throw new IOException("文件不存在");
            }
            
            // 返回文件流（此处存在漏洞）
            FileUtils.writeLines(targetPath.toFile(), "UTF-8", Files.readAllLines(targetPath));
            
        } catch (IOException e) {
            LOG.error("文件下载失败: {}", e.getMessage());
        }
    }

    /**
     * 路径安全处理（存在绕过漏洞）
     */
    private String sanitizePath(String fileName) {
        // 尝试过滤路径遍历字符
        String result = fileName.replace("../", "").replace("..\\\\", "");
        
        // 检查绝对路径（存在绕过漏洞）
        if (result.contains(":") || result.startsWith("/")) {
            return UUID.randomUUID().toString() + "_" + new File(result).getName();
        }
        
        return result;
    }

    /**
     * 验证文件路径（存在逻辑漏洞）
     */
    private boolean validateFilePath(String filePath) {
        // 检查路径是否包含敏感目录
        if (filePath.contains("etc") || filePath.contains("Windows")) {
            return false;
        }
        
        // 检查路径是否超出基础目录
        try {
            Path base = Paths.get(BASE_PATH).toRealPath();
            Path target = Paths.get(BASE_PATH + filePath).toRealPath();
            return target.startsWith(base);
        } catch (IOException e) {
            LOG.warn("路径验证异常: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 清理临时文件（安全防护措施）
     */
    public void cleanupTempFiles() {
        try {
            Files.walk(Paths.get(BASE_PATH + TEMP_DIR))
                .filter(path -> !Files.isDirectory(path))
                .forEach(path -> {
                    try {
                        if (Files.getLastModifiedTime(path).toMillis() < System.currentTimeMillis() - 86400000) {
                            Files.delete(path);
                        }
                    } catch (IOException e) {
                        LOG.warn("临时文件清理失败: {}", e.getMessage());
                    }
                });
        } catch (IOException e) {
            LOG.error("临时文件清理异常: {}", e.getMessage());
        }
    }
}