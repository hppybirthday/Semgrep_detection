package com.bank.security.vulnerable;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * 银行文档处理抽象基类
 * 模拟金融系统中常见的文档存储逻辑
 */
public abstract class AbstractBankDocumentService {
    // 系统文档存储根目录
    private final String storageRoot = "/var/bank_data/reports/";

    /**
     * 保存客户文档的抽象方法
     * @param documentPath 用户指定的文档路径
     * @param content 文档内容
     * @param clientId 客户ID
     * @return 存储后的文件路径
     * @throws IOException
     */
    public abstract String saveDocument(String documentPath, String content, String clientId) throws IOException;

    /**
     * 验证文件扩展名（示例方法，存在绕过风险）
     */
    protected boolean isValidExtension(String filename) {
        return filename.endsWith(".pdf") || filename.endsWith(".xlsx");
    }

    /**
     * 构建安全的文件路径（存在漏洞的实现）
     */
    protected String buildSecurePath(String basePath, String filename) {
        // 漏洞点：直接拼接路径和用户输入的文件名
        return storageRoot + basePath + File.separator + filename;
    }
}

/**
 * 本地文件存储实现类
 * 模拟银行实际文件存储逻辑
 */
class LocalBankDocumentService extends AbstractBankDocumentService {
    @Override
    public String saveDocument(String documentPath, String content, String clientId) throws IOException {
        // 检查客户端权限（简化实现）
        if (!isValidClient(clientId)) {
            throw new SecurityException("Unauthorized client access");
        }

        // 生成唯一文件名
        String safeFilename = generateSecureFilename(documentPath);
        
        // 漏洞触发点：构建文件路径
        String fullPath = buildSecurePath(documentPath, safeFilename);
        
        // 写入文件内容
        Path outputPath = Paths.get(fullPath);
        Files.write(outputPath, content.getBytes());
        
        return outputPath.toString();
    }

    /**
     * 生成安全的文件名（存在缺陷）
     */
    private String generateSecureFilename(String originalFilename) {
        // 漏洞：仅添加UUID前缀但保留原始文件扩展名
        String extension = originalFilename.substring(originalFilename.lastIndexOf("."));
        return UUID.randomUUID() + extension;
    }

    /**
     * 模拟客户端权限验证
     */
    private boolean isValidClient(String clientId) {
        // 简化的客户端验证逻辑
        return clientId != null && clientId.matches("CLIENT-\\\\d{6}");
    }
}

/**
 * 银行系统入口类
 * 模拟真实攻击场景
 */
public class BankSystem {
    public static void main(String[] args) {
        try {
            AbstractBankDocumentService documentService = new LocalBankDocumentService();
            
            // 模拟攻击者输入
            String maliciousPath = "../../../../etc";
            String maliciousFilename = "passwd";
            
            // 触发漏洞
            String resultPath = documentService.saveDocument(
                maliciousPath, 
                "hacked_content", 
                "CLIENT-000001"
            );
            
            System.out.println("Document saved at: " + resultPath);
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}