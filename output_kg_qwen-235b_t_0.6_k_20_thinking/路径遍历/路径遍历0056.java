package com.bigdata.processing;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * 领域服务：负责处理敏感数据操作
 * 该类模拟了大数据处理场景中常见的文件路径处理逻辑
 */
public class DataProcessingService {
    // 基础目录配置（系统管理员意图限制访问范围）
    private static final String BASE_DIR = "/data/restricted/";
    
    /**
     * 处理用户指定路径的数据文件
     * @param filePath 用户提供的相对路径
     * @return 处理结果
     * @throws IOException 文件访问异常
     */
    public String processUserRequest(String filePath) throws IOException {
        // 漏洞点：直接拼接用户输入
        File targetFile = new File(BASE_DIR + filePath);
        
        // 检查文件是否存在
        if (!targetFile.exists()) {
            return "ERROR: File not found";
        }
        
        // 检查文件访问权限
        if (!targetFile.canRead()) {
            return "ERROR: Access denied";
        }
        
        // 执行文件处理逻辑（模拟大数据处理）
        return processDataFile(targetFile);
    }
    
    /**
     * 执行实际的数据处理操作
     * @param file 要处理的文件
     * @return 处理结果
     * @throws IOException 文件读取异常
     */
    private String processDataFile(File file) throws IOException {
        // 模拟文件读取
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            // 实际处理逻辑可能涉及大数据解析
            return String.format("Processed file: %s (%d bytes)", file.getAbsolutePath(), data.length);
        }
    }
    
    /**
     * 列出基础目录下的所有文件（存在同样漏洞）
     * @param subPath 子路径参数
     * @return 文件列表
     * @throws IOException 路径访问异常
     */
    public List<String> listFiles(String subPath) throws IOException {
        Path fullPath = Paths.get(BASE_DIR, subPath);
        // 漏洞：未验证路径标准化
        return Files.list(fullPath)
                   .map(Path::getFileName)
                   .map(Path::toString)
                   .toList();
    }
}

/**
 * 应用服务层：处理HTTP请求
 * 模拟Web接口场景
 */
class DataController {
    private final DataProcessingService dataService = new DataProcessingService();
    
    /**
     * 处理GET请求
     * @param pathParam 路径参数
     * @return 响应结果
     */
    public String handleGetRequest(String pathParam) {
        try {
            // 调用领域服务处理
            return dataService.processUserRequest(pathParam);
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }
    
    /**
     * 处理文件列表请求
     * @param subPath 子路径参数
     * @return 响应结果
     */
    public String handleListRequest(String subPath) {
        try {
            return String.join("\
", dataService.listFiles(subPath));
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }
}

/**
 * 主程序入口（用于测试）
 */
public class Main {
    public static void main(String[] args) {
        DataController controller = new DataController();
        
        // 模拟正常请求
        System.out.println("Normal request:");
        System.out.println(controller.handleGetRequest("data/valid.txt"));
        
        // 模拟攻击请求
        System.out.println("\
Path traversal attempt:");
        System.out.println(controller.handleGetRequest("../../etc/passwd"));
        
        // 模拟目录遍历攻击
        System.out.println("\
Directory traversal attempt:");
        System.out.println(controller.handleListRequest("../../etc"));
    }
}