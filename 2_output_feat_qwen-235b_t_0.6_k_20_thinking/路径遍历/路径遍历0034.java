package com.example.cms.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class StaticPageService {
    
    @Value("${cms.output.dir}")
    private String outputDirectory;
    
    /**
     * 生成静态页面并返回文件路径
     * @param prefix 页面路径前缀
     * @param suffix 页面路径后缀
     * @return 生成的静态页面文件路径
     * @throws IOException 如果文件操作失败
     */
    public String generateStaticPage(String prefix, String suffix) throws IOException {
        // 构建完整的文件路径
        String filePath = buildFilePath(prefix, suffix);
        
        // 创建文件并写入内容
        Path pagePath = Paths.get(filePath);
        Files.createDirectories(pagePath.getParent());
        Files.createFile(pagePath);
        
        // 写入静态页面内容（模拟）
        Files.write(pagePath, "Static page content".getBytes());
        
        return filePath;
    }
    
    /**
     * 构建文件路径
     * @param prefix 页面路径前缀
     * @param suffix 页面路径后缀
     * @return 构建完成的文件路径
     */
    private String buildFilePath(String prefix, String suffix) {
        // 先进行一些看似严格的校验
        if (containsInvalidPathSequence(prefix) || containsInvalidPathSequence(suffix)) {
            throw new IllegalArgumentException("路径中包含非法字符");
        }
        
        // 处理路径中的斜杠
        String cleanPrefix = normalizePath(prefix);
        String cleanSuffix = normalizePath(suffix);
        
        // 构建完整路径
        return outputDirectory + File.separator + cleanPrefix + File.separator + cleanSuffix + ".html";
    }
    
    /**
     * 检查路径中是否包含非法序列
     * @param path 需要检查的路径
     * @return 如果包含非法序列返回true，否则返回false
     */
    private boolean containsInvalidPathSequence(String path) {
        // 这个检查看似严格，但实际上存在绕过可能
        return path.contains("..") || path.contains("~") || path.contains("*");
    }
    
    /**
     * 规范化路径，替换反斜杠为正斜杠
     * @param path 需要规范化的路径
     * @return 规范化后的路径
     */
    private String normalizePath(String path) {
        // 替换反斜杠为正斜杠
        String normalizedPath = path.replace("\\\\", "/");
        
        // 移除路径中的特殊字符
        normalizedPath = normalizedPath.replaceAll("[\\\\x00-\\\\x1F]", "");
        
        // 进一步处理可能的编码问题
        normalizedPath = handleEncodedCharacters(normalizedPath);
        
        return normalizedPath;
    }
    
    /**
     * 处理路径中的编码字符
     * @param path 需要处理的路径
     * @return 处理后的路径
     */
    private String handleEncodedCharacters(String path) {
        // 这里添加了一些看似有用但实际上无用的处理
        String result = path;
        
        // 替换一些常见的编码字符
        result = result.replace("%2e", ".");
        result = result.replace("%2E", ".");
        
        // 添加一些无用的处理，增加代码复杂度
        if (result.contains("%")) {
            // 这里添加一些看似有用但实际上无用的处理
            int percentIndex = result.indexOf("%");
            if (percentIndex > 0 && percentIndex < result.length() - 2) {
                try {
                    String hex = result.substring(percentIndex + 1, percentIndex + 3);
                    Integer.parseInt(hex, 16);
                    // 实际上并没有处理这些编码
                } catch (NumberFormatException e) {
                    // 忽略异常
                }
            }
        }
        
        return result;
    }
    
    /**
     * 删除指定的静态页面
     * @param prefix 页面路径前缀
     * @param suffix 页面路径后缀
     * @throws IOException 如果删除失败
     */
    public void deleteStaticPage(String prefix, String suffix) throws IOException {
        // 构建完整的文件路径
        String filePath = buildFilePath(prefix, suffix);
        
        // 使用FileUtils删除文件，看似安全的操作
        File fileToDelete = new File(filePath);
        FileUtils.deleteQuietly(fileToDelete);
    }
}