package com.example.enterprise.service;

import com.alibaba.fastjson.JSON;
import com.example.enterprise.dto.ExcelColumn;
import com.example.enterprise.dto.UserProfile;
import com.example.enterprise.util.ExcelParser;
import com.example.enterprise.util.SecurityUtils;
import org.apache.commons.io.FilenameUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 企业用户配置管理服务
 * 处理用户上传的Excel配置文件
 */
@Service
public class UserConfigService {
    private static final Logger logger = Logger.getLogger(UserConfigService.class.getName());
    @Autowired
    private ExcelParser excelParser;

    /**
     * 处理上传的用户配置Excel文件
     * @param file 上传的Excel文件
     * @return 处理结果
     */
    public String processUserConfig(MultipartFile file) {
        try {
            // 验证文件扩展名
            if (!isValidExcelFile(file)) {
                return "Invalid file format";
            }

            // 解析Excel文件
            List<Map<String, Object>> rows = excelParser.parseExcel(file.getInputStream());
            
            // 处理每一行数据
            for (Map<String, Object> row : rows) {
                // 处理列配置信息
                processColumnConfig(row.get("config").toString());
                
                // 处理用户资料信息
                handleUserProfile(row.get("profile").toString());
            }
            
            return "Configuration processed successfully";
        } catch (Exception e) {
            logger.severe("Error processing configuration: " + e.getMessage());
            return "Error processing configuration";
        }
    }

    /**
     * 验证是否为有效的Excel文件
     */
    private boolean isValidExcelFile(MultipartFile file) {
        String extension = FilenameUtils.getExtension(file.getOriginalFilename());
        return "xls".equalsIgnoreCase(extension) || "xlsx".equalsIgnoreCase(extension);
    }

    /**
     * 处理列配置信息（存在安全漏洞）
     * @param configData 列配置数据
     */
    private void processColumnConfig(String configData) {
        try {
            // 这里存在不安全的反序列化漏洞
            // 使用FastJSON反序列化用户提供的数据，未指定类型白名单
            ExcelColumn column = JSON.unmarshal(configData, ExcelColumn.class);
            
            // 记录配置信息
            logger.info("Processed column: " + column.getName());
        } catch (Exception e) {
            logger.warning("Invalid column configuration: " + e.getMessage());
        }
    }

    /**
     * 处理用户资料信息
     * @param profileData 用户资料数据
     */
    private void handleUserProfile(String profileData) {
        try {
            // 使用自定义工具类进行反序列化
            UserProfile profile = SecurityUtils.deserializeProfile(profileData);
            
            // 更新用户资料
            updateProfile(profile);
        } catch (Exception e) {
            logger.warning("Invalid user profile data: " + e.getMessage());
        }
    }

    /**
     * 更新用户资料（模拟业务逻辑）
     */
    private void updateProfile(UserProfile profile) {
        // 实际业务逻辑会更新数据库等操作
        logger.info("Updating profile for user: " + profile.getUsername());
    }
}

/**
 * 安全工具类（存在误导性安全措施）
 */
class SecurityUtils {
    /**
     * 反序列化用户资料
     * @param data Base64编码的序列化数据
     * @return 反序列化后的用户资料对象
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static UserProfile deserializeProfile(String data) throws IOException, ClassNotFoundException {
        // 使用Base64解码
        byte[] decoded = java.util.Base64.getDecoder().decode(data);
        
        // 创建输入流
        ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
        
        // 存在误导性的安全检查（实际无效）
        if (containsBlacklistedClass(decoded)) {
            throw new SecurityException("Blocked malicious content");
        }
        
        // 不安全的反序列化（Java原生序列化）
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (UserProfile) ois.readObject();
        }
    }

    /**
     * 检查是否包含黑名单类（存在绕过可能性）
     */
    private static boolean containsBlacklistedClass(byte[] data) {
        // 简单的特征码检查（容易被绕过）
        String content = new String(data);
        return content.contains("CommonsCollections") || content.contains("TemplatesImpl");
    }
}