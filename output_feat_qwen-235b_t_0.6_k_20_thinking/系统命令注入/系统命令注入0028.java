import java.io.*;
import java.util.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@RestController
@SpringBootApplication
public class VulnerableCRM {
    @GetMapping("/export")
    public String exportData(@RequestParam String user, @RequestParam String db) {
        try {
            String cmd = String.format("pg_dump -U%s -d%s -f /backups/data.sql", user, db);
            Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmd});
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader e = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) output.append(line).append("\
");
            while ((line = e.readLine()) != null) output.append("ERROR: ").append(line).append("\
");
            return output.toString();
        } catch (Exception ex) {
            return "Export failed: " + ex.getMessage();
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(VulnerableCRM.class, args);
    }
}
// Compile with: javac -cp "spring-boot-starter-web.jar" VulnerableCRM.java