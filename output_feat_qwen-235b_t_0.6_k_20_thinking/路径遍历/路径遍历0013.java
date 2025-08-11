import java.io.*;
import java.nio.file.*;
import java.util.*;

// 数学模型文件管理器
class ModelFileManager {
    private String baseDir = "models/";
    
    // 模拟BladeCodeGenerator.run()方法
    public static class BladeCodeGenerator {
        public static void run(String path) throws IOException {
            File file = new File(path);
            System.out.println("Reading file content from: " + file.getAbsolutePath());
            // 模拟实际文件操作
            if(file.exists()) {
                System.out.println("File content size: " + file.length() + " bytes");
            } else {
                System.out.println("File not found");
            }
        }
    }

    // AOP切面中的文件删除方法（存在漏洞）
    public void deleteModelFile(String pluginId) {
        try {
            // 漏洞点：直接拼接用户输入构造路径
            String prefix = baseDir + "plugins/";
            String suffix = ".model";
            String filePath = prefix + pluginId + suffix;
            
            // 模拟AOP切面执行
            new TemplateValidationAspect().deleteFileAdvice(filePath);
        } catch (Exception e) {
            System.err.println("Error deleting file: " + e.getMessage());
        }
    }

    // 主模拟程序
    public static void main(String[] args) {
        ModelFileManager manager = new ModelFileManager();
        
        // 模拟正常调用
        System.out.println("Normal execution:");
        manager.deleteModelFile("valid_plugin");
        
        // 模拟攻击载荷
        System.out.println("\
Malicious payload execution:");
        manager.deleteModelFile("../../etc/passwd");
    }
}

// 主题模板检查切面
class TemplateValidationAspect {
    public void deleteFileAdvice(String filePath) throws IOException {
        // 模拟文件操作前的验证
        System.out.println("Validating file path: " + filePath);
        
        // 调用BladeCodeGenerator执行文件操作
        ModelFileManager.BladeCodeGenerator.run(filePath);
    }
}