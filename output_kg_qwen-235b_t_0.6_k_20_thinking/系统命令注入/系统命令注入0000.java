import java.io.*;
import java.util.Scanner;

public class FileEncryptor {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.println("=== 文件加密解密工具 ===");
        System.out.print("请输入文件名: ");
        String filename = scanner.nextLine();
        System.out.print("请选择操作 (encrypt/decrypt): ");
        String operation = scanner.nextLine();

        try {
            // 漏洞点：直接拼接用户输入到命令中
            String command = "openssl " + operation + " -in " + filename + " -out " + filename + ".enc";
            System.out.println("正在执行命令: " + command);
            Process process = Runtime.getRuntime().exec(command);

            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));

            String line;
            System.out.println("命令输出:");
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            // 错误流处理
            while ((line = errorReader.readLine()) != null) {
                System.err.println(line);
            }

            process.waitFor();
            System.out.println("操作完成");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
编译运行说明:
1. 需要系统安装openssl工具
2. 示例攻击输入:
   文件名: "; rm -rf /tmp/test; echo "注入成功"
   操作: encrypt
3. 攻击者可以通过分号注入任意命令
4. 实际攻击可能使用更隐蔽的方式，如反引号或管道符
*/