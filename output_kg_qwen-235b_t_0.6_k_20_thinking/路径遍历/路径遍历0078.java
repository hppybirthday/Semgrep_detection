package com.example.vulnerablecloud.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 云存储抽象服务（存在路径遍历漏洞）
 */
public abstract class AbstractCloudStorageService {
    protected String storageRoot = "/var/storage/volumes/user_data";
    
    /**
     * 构建安全的存储路径
     * @param userProvidedPath 用户提供的路径
     * @return 安全的存储路径
     * @throws IOException 如果路径无效
     */
    protected String buildSafePath(String userProvidedPath) throws IOException {
        // 错误的路径拼接方式 - 直接拼接用户输入
        Path fullPath = Paths.get(storageRoot, userProvidedPath);
        
        // 本应验证路径是否在限定目录内
        // 但实际验证被错误实现
        if (!fullPath.normalize().startsWith(storageRoot)) {
            throw new IOException("Invalid path: " + userProvidedPath);
        }
        
        return fullPath.toString();
    }
    
    /**
     * 生成文件存储路径（存在漏洞）
     * @param prefix 用户提供的前缀
     * @param suffix 文件后缀
     * @return 文件存储路径
     */
    public String generateStoragePath(String prefix, String suffix) {
        String datePath = new java.text.SimpleDateFormat("yyyy/MM/dd").format(new Date());
        String uuid = UUID.randomUUID().toString().substring(0, 8);
        
        // 漏洞点：直接拼接用户输入的prefix
        return datePath + (prefix != null ? "/" + prefix : "") + "/" + uuid + "-" + suffix;
    }
    
    /**
     * 存储文件的抽象方法
     * @param data 文件数据
     * @param path 文件路径
     * @throws IOException 如果存储失败
     */
    public abstract void storeFile(byte[] data, String path) throws IOException;
    
    /**
     * 处理文件上传（存在漏洞）
     * @param data 文件数据
     * @param userPath 用户提供的路径
     * @param suffix 文件后缀
     * @throws IOException 如果上传失败
     */
    public void handleFileUpload(byte[] data, String userPath, String suffix) throws IOException {
        // 漏洞点：将用户输入直接传递给路径生成方法
        String storagePath = generateStoragePath(userPath, suffix);
        
        // 本应使用安全路径构建
        // String safePath = buildSafePath(storagePath);
        
        // 实际直接使用不安全路径
        storeFile(data, storagePath);
    }
    
    /**
     * 读取文件内容（存在漏洞）
     * @param filePath 要读取的文件路径
     * @return 文件内容
     * @throws IOException 如果读取失败
     */
    public byte[] readFileContent(String filePath) throws IOException {
        // 漏洞点：直接使用用户输入路径
        Path targetPath = Paths.get(storageRoot, filePath);
        return Files.readAllBytes(targetPath);
    }
}

/**
 * 本地文件存储实现（存在路径遍历漏洞）
 */
public class LocalFileStorageService extends AbstractCloudStorageService {
    @Override
    public void storeFile(byte[] data, String path) throws IOException {
        // 漏洞点：直接使用未经验证的路径
        Path targetPath = Paths.get(path);
        
        // 创建父目录（可能创建任意目录）
        Files.createDirectories(targetPath.getParent());
        
        // 写入文件（可能写入任意位置）
        Files.write(targetPath, data);
    }

    public static void main(String[] args) {
        try {
            LocalFileStorageService storage = new LocalFileStorageService();
            
            // 模拟攻击者上传
            String maliciousPath = "../../../../tmp/exploit";
            String suffix = "txt";
            
            System.out.println("[+] 正在模拟路径遍历攻击...");
            System.out.println("[i] 目标路径: " + maliciousPath);
            
            // 上传恶意文件
            storage.handleFileUpload("PWNED".getBytes(), maliciousPath, suffix);
            
            System.out.println("[+] 文件已上传，检查目标路径是否存在");
            
            // 尝试读取任意文件
            String readPath = "../../../../etc/passwd";
            byte[] content = storage.readFileContent(readPath);
            System.out.println("[+] 读取文件内容: " + new String(content).substring(0, 100));
            
        } catch (Exception e) {
            System.err.println("[-] 操作失败: " + e.getMessage());
        }
    }
}