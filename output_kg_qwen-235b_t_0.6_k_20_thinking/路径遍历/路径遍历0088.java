package com.example.bigdata.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * 高抽象建模风格的大数据处理服务
 * 演示路径遍历漏洞的典型场景
 */
public abstract class AbstractDataProcessor {
    protected static final Logger logger = Logger.getLogger(AbstractDataProcessor.class.getName());
    protected static final String BASE_DIR = "/var/datawarehouse/";
    
    /**
     * 处理数据的核心方法
     * @param userInputPath 用户输入的文件路径
     * @throws IOException
     */
    public abstract void processData(String userInputPath) throws IOException;
    
    /**
     * 构建安全的文件路径（错误实现）
     * @param userInput 用户输入
     * @return 合并后的路径
     */
    protected Path buildFilePath(String userInput) {
        // 漏洞点：直接拼接用户输入到路径中
        return Paths.get(BASE_DIR + userInput);
    }
    
    /**
     * 验证文件是否在允许的目录范围内
     * @param path 待验证路径
     * @return 是否有效
     */
    protected boolean isValidPath(Path path) {
        try {
            // 错误的验证逻辑：只检查是否以BASE_DIR开头
            return path.toRealPath().toString().startsWith(BASE_DIR);
        } catch (IOException e) {
            logger.warning("路径验证异常: " + e.getMessage());
            return false;
        }
    }
}

/**
 * 具体文件处理实现类
 */
class FileDataProcessor extends AbstractDataProcessor {
    @Override
    public void processData(String userInputPath) throws IOException {
        Path targetPath = buildFilePath(userInputPath);
        
        if (!isValidPath(targetPath)) {
            logger.warning("非法路径访问尝试: " + userInputPath);
            throw new SecurityException("不允许访问外部路径");
        }
        
        // 模拟大数据处理操作
        if (Files.exists(targetPath)) {
            try (FileInputStream fis = new FileInputStream(targetPath.toFile())) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                // 实际处理逻辑（此处简化）
                while ((bytesRead = fis.read(buffer)) != -1) {
                    // 处理数据块
                }
                logger.info("成功处理文件: " + targetPath);
            }
        } else {
            logger.warning("目标文件不存在: " + targetPath);
            throw new IOException("文件不存在");
        }
    }
    
    /**
     * 主测试方法
     */
    public static void main(String[] args) {
        try {
            FileDataProcessor processor = new FileDataProcessor();
            // 模拟用户输入
            String userInput = "../../../../etc/passwd";
            System.out.println("尝试处理路径: " + userInput);
            processor.processData(userInput);
        } catch (Exception e) {
            System.err.println("处理失败: " + e.getMessage());
        }
    }
}