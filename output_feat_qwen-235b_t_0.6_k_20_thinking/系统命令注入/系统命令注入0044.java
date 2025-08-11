import java.io.*;
import java.util.*;

/**
 * CRM系统文件上传处理模块
 * 模拟数据库工具类执行文件验证命令
 */
public class FileUploadHandler {
    
    // 模拟数据库工具类
    static class DatabaseUtil {
        public static boolean verifyFileMetadata(String filename) throws IOException {
            // 使用Windows批处理脚本验证文件元数据
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "verifyFile.bat " + filename);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            
            try (BufferedReader reader = new BufferedReader(
                 new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("[验证日志] " + line);
                }
            }
            
            return process.waitFor() == 0;
        }
    }

    // 文件上传处理器
    public boolean handleFileUpload(String uploadedFilename, String contentType) {
        // 防御式编程：验证文件类型
        if (!contentType.equals("application/pdf") && 
            !contentType.equals("image/jpeg")) {
            System.err.println("文件类型不合法");
            return false;
        }
        
        try {
            // 存储文件前执行安全验证
            if (!DatabaseUtil.verifyFileMetadata(uploadedFilename)) {
                System.err.println("文件元数据验证失败");
                return false;
            }
            
            // 实际存储文件逻辑（模拟）
            System.out.println("文件存储成功: " + uploadedFilename);
            return true;
            
        } catch (Exception e) {
            System.err.println("处理文件时发生错误: " + e.getMessage());
            return false;
        }
    }

    // 模拟Web端点
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("用法: java FileUploadHandler <文件名> <内容类型>");
            return;
        }
        
        FileUploadHandler handler = new FileUploadHandler();
        boolean result = handler.handleFileUpload(args[0], args[1]);
        System.out.println("上传结果: " + (result ? "成功" : "失败"));
    }
}