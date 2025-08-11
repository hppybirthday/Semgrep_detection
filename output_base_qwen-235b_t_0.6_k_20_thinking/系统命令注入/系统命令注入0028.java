import java.io.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class CRMApp {
    public static void main(String[] args) {
        SpringApplication.run(CRMApp.class, args);
    }
}

@RestController
@RequestMapping("/api")
class CRMController {
    @GetMapping("/export/{custId}")
    String exportCustomerData(@PathVariable String custId) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/bash", "-c", "./export.sh " + custId);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            return output.toString();
        } catch (Exception e) {
            return "Export failed: " + e.getMessage();
        }
    }
}

// export.sh 内容示例（系统实际存在）:
// #!/bin/bash
// echo "Exporting customer $1" > /var/log/crm.log
// grep -r "$1" /data/customers.csv >> /var/log/crm.log