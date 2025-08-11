import java.io.*;
import java.util.*;

// 模拟账户信息类
class AccountHead {
    private String fileName;
    
    public AccountHead(String fileName) {
        this.fileName = fileName;
    }
    
    public String getFileName() {
        return fileName;
    }
}

// 文件生成工具类
class GenerateUtil {
    public static boolean generateFile(String filePath, String content) {
        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(content);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}

// 页面生成服务类
class PageGenerator {
    private String baseDir;
    
    public PageGenerator(String baseDir) {
        this.baseDir = baseDir;
    }
    
    // 漏洞点：直接拼接用户输入生成路径
    public boolean generatePage(AccountHead account, String content, String suffix) {
        String unsafePath = baseDir + "/" + account.getFileName() + suffix;
        return GenerateUtil.generateFile(unsafePath, content);
    }
}

// 模拟HTTP请求处理
public class VulnerableCrawler {
    private static final String BASE_PATH = "/var/www/html";
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java VulnerableCrawler <filename> <content>");
            return;
        }
        
        // 模拟用户输入
        AccountHead account = new AccountHead(args[0]);
        String userInputContent = args[1];
        
        // 服务层调用
        PageGenerator generator = new PageGenerator(BASE_PATH);
        boolean success = generator.generatePage(account, userInputContent, ".html");
        
        System.out.println(success ? "Page generated successfully" : "Failed to generate page");
    }
}