package com.example.bigdata.security;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.UUID;
import java.util.logging.Logger;

/**
 * 大数据处理服务抽象类
 * 提供基础文件路径处理功能
 */
public abstract class AbstractDataProcessor {
    protected static final Logger logger = Logger.getLogger(AbstractDataProcessor.class.getName());
    protected final DataProcessingConfig config;

    public AbstractDataProcessor(DataProcessingConfig config) {
        this.config = config;
    }

    /**
     * 构建安全的文件路径
     * @param prefix 用户指定的路径前缀
     * @param suffix 文件后缀
     * @return 完整文件路径
     */
    public String buildSafePath(String prefix, String suffix) {
        String uuid = UUID.randomUUID().toString().replace("-", "");
        String datePath = String.format("%tF", new Date()).replace("-", "/");
        
        // 漏洞点：未清理用户输入的路径前缀
        return String.format("%s/%s/%s.%s", 
            config.getBaseDirectory(),
            prefix,
            uuid + "_" + datePath,
            suffix
        );
    }

    /**
     * 处理数据文件的抽象方法
     * @param data 文件内容
     * @param prefix 路径前缀
     * @param suffix 文件后缀
     * @return 文件存储路径
     * @throws IOException IO异常
     */
    public abstract String processData(byte[] data, String prefix, String suffix) throws IOException;
}

/**
 * 本地数据处理器实现
 */
public class LocalDataProcessor extends AbstractDataProcessor {
    public LocalDataProcessor(DataProcessingConfig config) {
        super(config);
    }

    @Override
    public String processData(byte[] data, String prefix, String suffix) throws IOException {
        String fullPath = buildSafePath(prefix, suffix);
        Path filePath = Paths.get(fullPath);
        
        // 创建目标目录
        Files.createDirectories(filePath.getParent());
        
        // 漏洞点：直接使用未经验证的路径写入文件
        Files.write(filePath, data);
        
        logger.info("数据文件已存储至: " + filePath.toAbsolutePath());
        return filePath.toString();
    }
}

/**
 * 数据处理配置类
 */
public class DataProcessingConfig {
    private String baseDirectory;

    public DataProcessingConfig(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public String getBaseDirectory() {
        return baseDirectory;
    }

    public void setBaseDirectory(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }
}

/**
 * 漏洞利用示例类
 */
public class VulnerabilityDemo {
    public static void main(String[] args) {
        try {
            // 初始化配置（使用系统临时目录作为示例）
            DataProcessingConfig config = new DataProcessingConfig(System.getProperty("java.io.tmpdir"));
            AbstractDataProcessor processor = new LocalDataProcessor(config);
            
            // 恶意输入示例
            String maliciousPrefix = "../../../../etc/security";
            String suffix = "conf";
            
            // 构造恶意数据
            byte[] payload = "malicious_content".getBytes();
            
            // 触发漏洞
            String resultPath = processor.processData(payload, maliciousPrefix, suffix);
            System.out.println("文件实际写入路径: " + resultPath);
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}