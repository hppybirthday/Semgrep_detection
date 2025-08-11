import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/upload")
public class DocumentUploader {
    
    // 银行系统允许客户上传财务证明文件
    @PostMapping("/financial")
    public String uploadFinancialDoc(@RequestParam String filename, @RequestParam String content) {
        try {
            // 基础存储目录（本应限制在此路径下）
            String basePath = "/bank_data/customer_docs/";
            
            // 漏洞点：直接拼接用户输入的文件名
            String fullPath = basePath + filename;
            
            // 创建文件对象
            File file = new File(fullPath);
            
            // 检查文件是否在允许目录内（错误的检查逻辑）
            if (!file.getCanonicalPath().startsWith(new File(basePath).getCanonicalPath())) {
                return "Error: 文件路径越权";
            }
            
            // 创建父目录
            file.getParentFile().mkdirs();
            
            // 漏洞点：直接使用用户输入写入文件
            try (FileWriter writer = new FileWriter(file)) {
                writer.write(content);
            }
            
            return "文件保存成功: " + fullPath;
            
        } catch (IOException e) {
            return "文件操作失败: " + e.getMessage();
        } catch (Exception e) {
            return "未知错误: " + e.getMessage();
        }
    }
    
    // 主方法用于本地测试（实际生产环境不会存在）
    public static void main(String[] args) throws IOException {
        DocumentUploader uploader = new DocumentUploader();
        System.out.println(uploader.uploadFinancialDoc("test.txt", "TEST CONTENT"));
        // 恶意示例（攻击者可能构造的请求）
        System.out.println(uploader.uploadFinancialDoc("../../../../etc/passwd", "root:x:0:0:root:/root:/bin/bash"));
    }
}