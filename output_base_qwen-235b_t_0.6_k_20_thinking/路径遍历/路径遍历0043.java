import java.io.*;
import java.util.Scanner;

// 文件管理类
class FileManager {
    private String baseDir = "/bank_data/customer_docs/";
    
    public String readFile(String relativePath) throws IOException {
        // 漏洞点：未正确验证路径
        File file = new File(baseDir + relativePath);
        
        if (!file.exists()) {
            return "文件不存在";
        }
        
        // 读取文件内容
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

// 银行服务类
class BankService {
    private FileManager fileManager = new FileManager();
    
    public String downloadCustomerTransactionReport(String customerId, String fileName) {
        try {
            // 构造文件路径
            String filePath = customerId + "/transactions/" + fileName;
            return fileManager.readFile(filePath);
        } catch (Exception e) {
            return "操作失败: " + e.getMessage();
        }
    }
}

// 恶意客户端示例
public class BankingSystem {
    public static void main(String[] args) {
        BankService bank = new BankService();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== 银行交易报告下载系统 ===");
        System.out.print("请输入客户ID: ");
        String customerId = scanner.nextLine();
        System.out.print("请输入文件名: ");
        String fileName = scanner.nextLine();
        
        // 模拟下载操作
        System.out.println("\
--- 文件内容 ---");
        System.out.println(bank.downloadCustomerTransactionReport(customerId, fileName));
    }
}