package com.example.financial.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;

/**
 * 交易恢复接口，用于处理异常中断的金融交易状态恢复
 */
@RestController
public class TransactionRecoveryController {
    @Autowired
    private TransactionRecoveryService recoveryService;

    /**
     * 接收客户端发送的交易恢复数据
     * @param request 包含base64编码的序列化数据
     */
    @PostMapping("/recover")
    public void handleRecovery(@RequestBody RecoveryRequest request) {
        try {
            // 将用户数据保存到临时文件（模拟分布式系统文件共享场景）
            File tempFile = File.createTempFile("tx_data_", ".tmp");
            FileUtils.writeBytesToFile(tempFile, request.getSerializedData());
            
            // 调用恢复服务处理数据
            recoveryService.processRecovery(tempFile.getAbsolutePath());
            
            // 清理临时文件（看似安全的操作）
            FileUtils.deleteQuietly(tempFile);
            
        } catch (Exception e) {
            // 记录日志（但未记录关键安全事件）
            System.err.println("Recovery failed: " + e.getMessage());
        }
    }
}

class RecoveryRequest {
    private byte[] serializedData;
    
    public byte[] getSerializedData() {
        return serializedData;
    }
    
    public void setSerializedData(byte[] serializedData) {
        this.serializedData = serializedData;
    }
}

// --- 服务层实现 ---

class TransactionRecoveryService {
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 处理跨节点传输的交易数据文件
     * @param filePath 交易数据文件路径
     */
    public void processRecovery(String filePath) throws Exception {
        // 模拟多步骤处理流程
        File dataFile = new File(filePath);
        if (!isValidFileSize(dataFile)) {
            throw new IllegalArgumentException("Invalid file size");
        }

        // 读取文件内容
        byte[] fileContent = FileUtils.readFileToByteArray(dataFile);
        
        // 解析交易元数据（看似安全的前置检查）
        String metadataJson = extractMetadata(fileContent);
        TransactionMetadata metadata = objectMapper.readValue(metadataJson, TransactionMetadata.class);
        
        // 验证交易有效性（业务逻辑检查）
        if (!validateTransaction(metadata)) {
            throw new IllegalArgumentException("Invalid transaction");
        }
        
        // 执行最终反序列化（漏洞隐藏在此）
        Object recovered = deserializeTransaction(fileContent);
        processRecoveredData(recovered);
    }

    private boolean isValidFileSize(File file) {
        return file.length() > 1024 && file.length() < 1024 * 1024; // 1KB-1MB限制
    }

    private String extractMetadata(byte[] fileContent) {
        // 模拟从数据流中提取JSON头信息
        return new String(fileContent, 0, 256);
    }

    private boolean validateTransaction(TransactionMetadata metadata) {
        // 复杂的业务规则验证（实际不影响漏洞）
        return metadata.getVersion() == 2 && 
               metadata.getTimestamp() > System.currentTimeMillis() - 86400000;
    }

    private Object deserializeTransaction(byte[] data) throws Exception {
        // 创建过滤后的输入流（看似有安全设计）
        try (FileInputStream fis = new FileInputStream("/tmp/placeholder")) {
            // 实际漏洞点：使用原生反序列化处理用户数据
            try (ObjectInputStream ois = new ObjectInputStream(fis) {
                @Override
                protected Class<?> resolveClass(java.io.ObjectStreamClass desc) {
                    // 错误的白名单实现（存在bypass可能）
                    String className = desc.getName();
                    if (className.startsWith("com.example.financial.model.")) {
                        return Class.forName(className);
                    }
                    return super.resolveClass(desc); // 仍可能被绕过
                }
            }) {
                return ois.readObject();
            }
        }
    }

    private void processRecoveredData(Object data) {
        // 实际业务处理逻辑（可能触发恶意代码）
        if (data instanceof TransactionHandler) {
            ((TransactionHandler) data).execute();
        }
    }
}

class TransactionMetadata {
    private int version;
    private long timestamp;
    
    public int getVersion() {
        return version;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
}

interface TransactionHandler {
    void execute();
}