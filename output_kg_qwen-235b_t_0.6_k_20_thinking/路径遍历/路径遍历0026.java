package com.bank.document.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

/**
 * 银行文档管理系统核心服务
 * 实现客户文件上传功能，包含漏洞路径遍历风险
 */
public class DocumentService {
    private static final Logger logger = Logger.getLogger(DocumentService.class.getName());
    private final String baseStoragePath = "/var/bank_data/customer_documents";

    /**
     * 处理客户文件上传
     * @param customerId 客户唯一标识
     * @param fileName 用户提交的文件名
     * @param content 文件内容字节数组
     * @return 文件存储路径
     * @throws IOException 文件操作异常
     */
    public String uploadDocument(String customerId, String fileName, byte[] content) throws IOException {
        // 领域模型验证
        if (customerId == null || customerId.trim().isEmpty()) {
            throw new IllegalArgumentException("客户ID不能为空");
        }

        // 漏洞点：未正确验证文件名
        Path targetPath = getSafeFilePath(customerId, fileName);
        
        // 创建存储目录
        Files.createDirectories(targetPath.getParent());
        
        // 写入文件内容
        Files.write(targetPath, content);
        
        logger.info(String.format("文档已存储: %s for customer %s", targetPath, customerId));
        return targetPath.toString();
    }

    /**
     * 构建安全的文件存储路径（存在漏洞的实现）
     * @param customerId 客户ID
     * @param fileName 用户提供的文件名
     * @return 安全的文件路径
     */
    private Path getSafeFilePath(String customerId, String fileName) {
        // 漏洞根源：简单拼接路径，未处理路径穿越字符
        String unsafePath = baseStoragePath + File.separator + customerId + File.separator + fileName;
        
        // 错误的安全验证：仅检查前缀
        if (!unsafePath.startsWith(baseStoragePath)) {
            throw new SecurityException("路径越权访问");
        }
        
        return Paths.get(unsafePath);
    }

    /**
     * 模拟银行系统文件访问接口
     */
    public static class DocumentController {
        private final DocumentService documentService = new DocumentService();

        /**
         * REST接口模拟（简化版）
         * @param customerId 客户ID
         * @param fileName 文件名
         * @param content 文件内容
         * @throws Exception
         */
        public void handleUpload(String customerId, String fileName, byte[] content) throws Exception {
            try {
                documentService.uploadDocument(customerId, fileName, content);
                System.out.println("上传成功");
            } catch (Exception e) {
                System.err.println("上传失败: " + e.getMessage());
                throw e;
            }
        }
    }

    public static void main(String[] args) {
        try {
            DocumentController controller = new DocumentController();
            
            // 正常上传示例
            controller.handleUpload("C1001", "passport.pdf", "NORMAL_CONTENT".getBytes());
            
            // 恶意上传示例：尝试写入系统文件
            controller.handleUpload("C1001", "../../../../../tmp/bank_config.txt", "MALICIOUS_DATA".getBytes());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}