import java.util.function.Function;
import java.io.BufferedReader;
import java.io.InputStreamReader;

@FunctionalInterface
interface DataImporter {
    String importData(String input) throws Exception;
}

public class CRMService {
    public static void main(String[] args) {
        DataImporter importer = (filePath) -> {
            Process process = Runtime.getRuntime().exec(
                "cat " + filePath);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
        };

        try {
            System.out.println("Enter customer data file path:");
            java.util.Scanner scanner = new java.util.Scanner(System.in);
            String userInput = scanner.nextLine();
            
            // 漏洞点：直接拼接用户输入到系统命令中
            String result = importer.importData(userInput);
            System.out.println("Import result:\
" + result);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
编译运行示例：
1. 创建测试文件：echo "test_data" > /tmp/test.txt
2. 正常使用：输入 /tmp/test.txt
3. 攻击演示：输入 "; rm -rf / "
*/