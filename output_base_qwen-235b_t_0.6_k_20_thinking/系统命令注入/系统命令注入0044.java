import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Scanner;

public class CustomerReportExporter {
    // 模拟CRM系统中导出客户报告的功能
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== CRM Customer Report Exporter ===");
        System.out.print("Enter Customer ID to export: ");
        
        String customerId = scanner.nextLine();
        
        // 模拟生成CSV报告并压缩的系统命令
        // 漏洞点：直接拼接用户输入到命令链中
        String command = "cmd /c echo Generating report... && " + 
                        "type NUL > customer_data_" + customerId + ".csv && " +
                        "zip -r customer_report_" + customerId + ".zip " +
                        "customer_data_" + customerId + ".csv";

        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("Output: " + line);
            }
            
            while ((line = errorReader.readLine()) != null) {
                System.err.println("Error: " + line);
            }
            
            int exitCode = process.waitFor();
            System.out.println("Export process exited with code " + exitCode);
            
        } catch (IOException | InterruptedException e) {
            // 漏洞：过于宽泛的异常捕获掩盖潜在问题
            System.err.println("Export failed: " + e.getMessage());
        }
        
        System.out.println("=== Export Process Complete ===");
    }
    
    // 模拟防御措施的虚假安全实现
    private static boolean validateCustomerId(String id) {
        // 漏洞：不完整的输入验证（仅检查非空）
        return id != null && !id.trim().isEmpty();
    }
}