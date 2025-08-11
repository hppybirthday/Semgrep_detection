import java.io.*;
import java.util.*;
import java.util.function.*;
import java.nio.file.*;

public class FileDownloadService {
    private static final String BASE_PATH = "/var/crm/uploads/";
    
    public static void main(String[] args) {
        Function<Map<String, String>, String> buildPath = params -> {
            String prefix = params.getOrDefault("prefix", "user_123/");
            String filename = params.get("filename");
            String suffix = params.getOrDefault("suffix", ".pdf");
            // 路径拼接逻辑存在漏洞
            return BASE_PATH + prefix + filename + suffix;
        };
        
        Consumer<Map<String, String>> downloadFile = params -> {
            try {
                String filePath = buildPath.apply(params);
                Path targetPath = Paths.get(filePath);
                
                // 模拟文件下载
                if (Files.exists(targetPath)) {
                    System.out.println("开始下载文件: " + filePath);
                    // 实际场景中可能调用云存储SDK下载
                    // cloudStorage.download(targetPath.toString());
                } else {
                    System.out.println("文件不存在: " + filePath);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
        
        // 模拟正常请求
        Map<String, String> normalRequest = new HashMap<>();
        normalRequest.put("filename", "contract");
        downloadFile.accept(normalRequest);
        
        // 模拟攻击请求
        Map<String, String> attackRequest = new HashMap<>();
        attackRequest.put("prefix", "../../../../etc/");
        attackRequest.put("filename", "passwd");
        attackRequest.put("suffix", "");
        downloadFile.accept(attackRequest);
    }
}