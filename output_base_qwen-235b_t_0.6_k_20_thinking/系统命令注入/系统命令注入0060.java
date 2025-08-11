import java.io.*;
import java.util.Scanner;

public class CRMExport {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("CRM客户数据导出系统");
        System.out.print("请输入客户ID: ");
        String clientId = scanner.nextLine();
        System.out.print("请输入导出文件名（不带扩展名）: ");
        String filename = scanner.nextLine();
        
        try {
            // 模拟生成CSV文件
            BufferedWriter writer = new BufferedWriter(
                new FileWriter(filename + ".csv"));
            writer.write("ID,Name,Email\
");
            writer.write(clientId + ",John Doe,john@example.com\
");
            writer.close();
            
            // 构造压缩命令（存在漏洞的关键点）
            String command = "zip -r " + filename + ".zip " + filename + ".csv";
            System.out.println("执行命令: " + command);
            
            // 执行系统命令（危险操作）
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader input = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader error = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String line;
            while ((line = input.readLine()) != null) {
                System.out.println("输出: " + line);
            }
            while ((line = error.readLine()) != null) {
                System.err.println("错误: " + line);
            }
            
            // 清理临时文件
            new File(filename + ".csv").delete();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}