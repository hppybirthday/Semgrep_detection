package com.bank.security;

import java.io.*;
import java.util.logging.*;

/**
 * 银行文档服务类，处理客户文档读取操作
 * 存在路径遍历漏洞
 */
public class BankDocumentService {
    private static final Logger logger = Logger.getLogger(BankDocumentService.class.getName());
    private static final String BASE_DIR = "/var/bank/customer_documents/";

    /**
     * 读取客户文档内容
     * @param customerId 客户ID
     * @param fileName 文件名
     * @return 文件内容
     * @throws IOException 文件读取异常
     */
    public String readCustomerDocument(String customerId, String fileName) throws IOException {
        // 构造文件路径：/var/bank/customer_documents/{customerId}/{fileName}
        String filePath = BASE_DIR + customerId + "/" + fileName;
        
        // 漏洞点：未验证路径是否包含../等特殊字符
        File file = new File(filePath);
        
        // 记录访问路径用于审计
        logger.log(Level.INFO, "Accessing file: {0}", file.getAbsolutePath());
        
        // 检查文件是否存在
        if (!file.exists()) {
            throw new FileNotFoundException("Document not found");
        }
        
        // 读取文件内容
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append(System.lineSeparator());
            }
        }
        return content.toString();
    }
    
    /**
     * 验证客户ID格式（仅允许字母数字）
     */
    private boolean isValidCustomerId(String customerId) {
        return customerId != null && customerId.matches("[a-zA-Z0-9]+");
    }
    
    /**
     * 主方法用于演示漏洞
     */
    public static void main(String[] args) {
        BankDocumentService service = new BankDocumentService();
        try {
            // 正常用例
            System.out.println("Normal case:");
            System.out.println(service.readCustomerDocument("C123456", "account_statement.txt"));
            
            // 恶意用例 - 路径遍历攻击
            System.out.println("\
Malicious case (path traversal):);
            System.out.println(service.readCustomerDocument("C123456", "../../../../../etc/passwd"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/**
 * 银行文档控制器（模拟Web层）
 */
class DocumentController {
    private BankDocumentService documentService = new BankDocumentService();
    
    /**
     * 处理文档请求
     * @param customerId 客户ID
     * @param fileName 文件名
     */
    public void handleDocumentRequest(String customerId, String fileName) {
        try {
            if (!documentService.isValidCustomerId(customerId)) {
                System.out.println("Invalid customer ID format");
                return;
            }
            
            String content = documentService.readCustomerDocument(customerId, fileName);
            System.out.println("Document content: " + content);
        } catch (IOException e) {
            System.out.println("Error reading document: " + e.getMessage());
        }
    }
}