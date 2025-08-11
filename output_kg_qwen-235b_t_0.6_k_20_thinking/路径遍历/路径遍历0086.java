package com.gamestudio.core.domain.model;

import java.io.*;
import java.nio.file.*;
import java.util.*;

/**
 * 游戏资源服务类，负责处理游戏资源文件的加载
 * 采用领域驱动设计风格实现
 */
public class GameResourceService {
    // 游戏资源基础目录
    private final Path baseResourceDir;
    
    public GameResourceService(String resourceBasePath) {
        this.baseResourceDir = Paths.get(resourceBasePath).toAbsolutePath().normalize();
        if (!Files.exists(baseResourceDir)) {
            try {
                Files.createDirectories(baseResourceDir);
            } catch (IOException e) {
                throw new RuntimeException("无法创建资源目录: " + baseResourceDir, e);
            }
        }
    }

    /**
     * 加载指定名称的游戏资源文件
     * 存在路径遍历漏洞
     * @param resourceName 用户输入的资源名称
     * @return 资源内容
     * @throws IOException 文件操作异常
     */
    public String loadResource(String resourceName) throws IOException {
        // 漏洞点：直接拼接用户输入到文件路径中
        Path targetPath = baseResourceDir.resolve(resourceName).normalize();
        
        // 检查是否在允许的目录范围内
        if (!targetPath.startsWith(baseResourceDir)) {
            throw new SecurityException("禁止访问外部路径: " + targetPath);
        }
        
        if (!Files.exists(targetPath)) {
            throw new FileNotFoundException("资源文件不存在: " + resourceName);
        }
        
        try (BufferedReader reader = Files.newBufferedReader(targetPath)) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
            return content.toString();
        }
    }
    
    /**
     * 保存游戏配置文件
     * @param configName 配置文件名
     * @param content 配置内容
     * @throws IOException 文件写入异常
     */
    public void saveConfig(String configName, String content) throws IOException {
        Path configPath = baseResourceDir.resolve("configs").resolve(configName).normalize();
        
        if (!configPath.startsWith(baseResourceDir)) {
            throw new SecurityException("禁止写入外部路径: " + configPath);
        }
        
        if (!Files.exists(configPath.getParent())) {
            Files.createDirectories(configPath.getParent());
        }
        
        try (BufferedWriter writer = Files.newBufferedWriter(configPath)) {
            writer.write(content);
        }
    }
    
    /**
     * 获取资源文件列表
     * @return 资源名称列表
     * @throws IOException 文件访问异常
     */
    public List<String> listResources() throws IOException {
        List<String> resources = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(baseResourceDir)) {
            for (Path path : stream) {
                resources.add(path.getFileName().toString());
            }
        }
        return resources;
    }
    
    /*
     * 测试用例（实际使用时应移除）
     */
    public static void main(String[] args) {
        GameResourceService service = new GameResourceService("./game_resources");
        try {
            // 正常用例
            System.out.println("加载正常资源: " + service.loadResource("level1.map"));
            
            // 恶意用例（触发漏洞）
            // System.out.println("尝试读取系统文件: " + service.loadResource("../../../../etc/passwd"));
            
            // 写入测试
            service.saveConfig("test.cfg", "resolution=1920x1080\
fullscreen=true");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}