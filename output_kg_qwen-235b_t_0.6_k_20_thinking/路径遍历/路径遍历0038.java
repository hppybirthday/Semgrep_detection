package com.gamestudio.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 游戏资源管理器（存在路径遍历漏洞）
 */
public class GameResourceManager {
    // 游戏资源基目录
    private final String baseResourcePath;
    // 安全验证白名单
    private final List<String> allowedExtensions = List.of(".png", ".jpg", ".json", ".mp3");

    public GameResourceManager(String baseResourcePath) {
        this.baseResourcePath = baseResourcePath;
    }

    /**
     * 加载资源文件（存在漏洞的实现）
     */
    public byte[] loadResource(String resourcePath) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        Path fullPath = Paths.get(baseResourcePath, resourcePath);
        
        // 验证文件扩展名（安全验证不完整）
        if(!allowedExtensions.contains(getFileExtension(fullPath.toString()))) {
            throw new SecurityException("不允许加载该类型文件");
        }

        // 漏洞危害：攻击者可通过../访问任意文件
        System.out.println("正在加载资源: " + fullPath.toAbsolutePath());
        return Files.readAllBytes(fullPath);
    }

    /**
     * 获取文件扩展名
     */
    private String getFileExtension(String filePath) {
        int dotIndex = filePath.lastIndexOf(".");
        return (dotIndex == -1) ? "" : filePath.substring(dotIndex);
    }

    /**
     * 列出资源目录内容（存在漏洞的实现）
     */
    public List<String> listResources(String dirPath) throws IOException {
        // 漏洞点：用户输入路径未净化
        File targetDir = new File(Paths.get(baseResourcePath, dirPath).toString());
        
        if(!targetDir.exists() || !targetDir.isDirectory()) {
            throw new IllegalArgumentException("目录不存在");
        }

        // 漏洞危害：可列出任意目录内容
        return Files.list(targetDir.toPath())
                   .map(Path::getFileName)
                   .map(Path::toString)
                   .collect(Collectors.toList());
    }

    /**
     * 模拟游戏启动器
     */
    public static void main(String[] args) {
        try {
            // 初始化资源管理器
            GameResourceManager resourceManager = new GameResourceManager("./game_resources");
            
            // 模拟用户输入（攻击向量）
            if(args.length == 0) {
                System.out.println("请指定资源路径");
                return;
            }
            
            // 漏洞利用示例：输入"../../../../../etc/passwd"
            byte[] resourceData = resourceManager.loadResource(args[0]);
            System.out.println("加载成功，数据大小: " + resourceData.length + " bytes");
            
        } catch (Exception e) {
            System.err.println("错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
}