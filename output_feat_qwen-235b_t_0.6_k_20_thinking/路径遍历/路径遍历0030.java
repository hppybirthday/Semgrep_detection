import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileService {
    private static final String BASE_DIR = "/data/data/com.example.app/files/";
    
    // 模拟用户上传文件处理
    public void processUserFile(String prefix, String suffix) {
        String fullPath = BASE_DIR + prefix + "/uploads/" + suffix;
        
        // 创建存储目录
        File dir = new File(fullPath);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        // 写入示例文件
        try (FileOutputStream fos = new FileOutputStream(fullPath + "/test.txt")) {
            fos.write("Vulnerable content".getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    // 模拟文件下载接口（存在漏洞）
    public File getFileForDownload(String prefix, String filename) {
        // 危险的路径构造方式
        String filePath = BASE_DIR + prefix + "/downloads/" + filename;
        File file = new File(filePath);
        
        // 本应限制在指定目录，但未进行路径规范化检查
        if (!file.exists()) {
            System.out.println("File not found: " + filePath);
            return null;
        }
        
        return file;
    }
    
    // 攻击者可能利用的恶意路径示例
    public static void main(String[] args) {
        FileService service = new FileService();
        
        // 正常调用示例
        System.out.println("Normal case:");
        service.processUserFile("user123", "profile.jpg");
        
        // 恶意攻击示例（路径遍历）
        System.out.println("\
Malicious attack case:");
        // 攻击者构造特殊参数
        String maliciousPrefix = "../../../../etc";
        String maliciousFilename = "passwd";
        
        // 尝试访问系统文件
        File attackFile = service.getFileForDownload(maliciousPrefix, maliciousFilename);
        if (attackFile != null) {
            System.out.println("Attack succeeded! Accessed file: " + attackFile.getAbsolutePath());
        } else {
            System.out.println("Attack failed");
        }
    }
}