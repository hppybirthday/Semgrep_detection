import java.io.*;
import java.nio.file.*;
import java.util.*;

public class VulnerableFileManager {
    // 基础目录限制
    private static final String BASE_DIR = System.getProperty("user.dir") + "/user_files/";
    
    /**
     * 提供文件读取功能
     * @param fileName 用户提交的文件名参数
     * @return 文件内容字符串
     */
    public String readFile(String fileName) throws IOException {
        // 防御式检查1：防止空值
        if (fileName == null || fileName.isEmpty()) {
            throw new IllegalArgumentException("文件名不能为空");
        }
        
        // 防御式检查2：尝试阻止路径遍历
        if (containsTraversal(fileName)) {
            throw new SecurityException("非法路径字符");
        }
        
        // 构造文件路径
        Path filePath = Paths.get(BASE_DIR + fileName);
        
        // 防御式检查3：确保路径在限定目录内
        if (!filePath.normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("路径超出允许范围");
        }
        
        // 读取文件内容
        return new String(Files.readAllBytes(filePath));
    }
    
    /**
     * 检查路径遍历特征（存在缺陷）
     */
    private boolean containsTraversal(String path) {
        // 仅检查原始形式的../序列
        return path.contains("..") || path.contains("~");
    }
    
    /**
     * 文件写入功能
     * @param fileName 目标文件名
     * @param content 写入内容
     */
    public void writeFile(String fileName, String content) throws IOException {
        // 复用路径检查逻辑
        Path filePath = Paths.get(BASE_DIR + fileName);
        
        // 使用相同的防御检查
        if (containsTraversal(fileName) || 
            !filePath.normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("路径校验失败");
        }
        
        // 写入文件
        Files.write(filePath, content.getBytes());
    }
    
    // 测试漏洞案例
    public static void main(String[] args) {
        VulnerableFileManager manager = new VulnerableFileManager();
        
        try {
            // 构造特殊编码的路径遍历攻击
            String attackPath = "..%5c..%5c..%5cetc%5cpasswd"; // URL编码绕过检查
            System.out.println("尝试读取系统文件...");
            String result = manager.readFile(attackPath);
            System.out.println("攻击成功，读取到内容长度：" + result.length());
        } catch (Exception e) {
            System.out.println("防御生效：" + e.getMessage());
        }
    }
}