import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }

    @GetMapping("/export")
    public String exportCustomerData(@RequestParam String customerId) {
        try {
            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "echo Exporting customer data to C:\\\\\\\\export\\\\\\\\customer_" + customerId + ".csv && some_export_command.exe -id " + customerId);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            return output.toString();
            
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}

// 模拟业务场景：CRM系统需要导出客户数据到本地目录
// 漏洞点：直接将用户输入的customerId拼接到命令字符串中
// 攻击示例：http://localhost:8080/export?customerId=12345%20%26%26%20del%20%2FQ%20C:\\\\*.*