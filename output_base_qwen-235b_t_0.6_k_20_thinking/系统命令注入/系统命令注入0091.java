import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class FinancialReportSystem {
    public static void main(String[] args) {
        SpringApplication.run(FinancialReportSystem.class, args);
    }
}

@RestController
class ReportController {
    @GetMapping("/generate")
    public String generateReport(@RequestParam String customerId, @RequestParam String fileName) {
        try {
            // 模拟生成报告文件
            ProcessBuilder reportGen = new ProcessBuilder("touch", "/reports/customer_" + customerId + "_data.txt");
            reportGen.start().waitFor();
            
            // 存在漏洞的命令执行
            Process process = Runtime.getRuntime().exec(
                "zip -r /exports/" + fileName + " /reports/customer_" + customerId + "_data.txt"
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            return "Report generated: " + reader.readLine();
            
        } catch (Exception e) {
            return "Error generating report: " + e.getMessage();
        }
    }
}

// 漏洞触发示例：
// curl "http://localhost:8080/generate?customerId=123&fileName=test%3B+rm+-rf+%2F"