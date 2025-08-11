import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;

public class CRMCategoriesManager {
    private static final String BASE_DIR = "/var/www/html/crm_uploads/";
    
    public static void main(String[] args) {
        // 模拟分类添加请求
        String userInput = "../../../tmp/evil.txt"; // 恶意输入
        String fileContent = "malicious_content";
        
        try {
            addCategory(userInput, fileContent.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void addCategory(String categoryName, byte[] fileData) throws IOException {
        // 路径构造过程直接拼接用户输入
        String fullPath = BASE_DIR + categoryName;
        File targetFile = new File(fullPath);
        
        // 创建父目录（可能创建任意路径）
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 存在漏洞的文件写入操作
        FileUtils.writeBytesToFile(targetFile, fileData);
        System.out.println("文件已保存至: " + fullPath);
        
        // 模拟后续操作
        updateCategoryInfo(categoryName);
    }
    
    private static void updateCategoryInfo(String name) {
        // 实际业务逻辑可能包含文件读取操作
        File f = new File(BASE_DIR + name);
        System.out.println("文件大小: " + f.length() + " bytes");
    }
    
    // 模拟分类更新功能
    public static void updateCategory(String oldName, String newName) {
        File oldFile = new File(BASE_DIR + oldName);
        File newFile = new File(BASE_DIR + newName);
        
        if (oldFile.exists()) {
            oldFile.renameTo(newFile);
        }
    }
}