import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class BankingApp {
    public static void main(String[] args) {
        SpringApplication.run(BankingApp.class, args);
    }
}

@RestController
class BackupController {
    @GetMapping("/backup")
    public String triggerBackup(@RequestParam String dbHost, @RequestParam String dbUser, @RequestParam String dbPassword) {
        try {
            // Vulnerable command construction
            String command = "mysqldump -h " + dbHost + " -u" + dbUser + " -p" + dbPassword + " --set-charset=utf8 banking_data";
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", command);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }
    
    // Simulated admin endpoint for host validation
    @GetMapping("/validate-host")
    public String validateHost(@RequestParam String host) {
        try {
            // Vulnerable ping command
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ping -c 4 " + host);
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
            return "Validation failed: " + e.getMessage();
        }
    }
}