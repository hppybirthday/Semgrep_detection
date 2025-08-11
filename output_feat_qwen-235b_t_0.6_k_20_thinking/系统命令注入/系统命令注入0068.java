import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
@RestController
public class JobScheduler {
    public static void main(String[] args) {
        SpringApplication.run(JobScheduler.class, args);
    }

    @PostMapping("/schedule")
    public String scheduleJob(@RequestParam String jobId) {
        try {
            String cmd = "sh -c /path/to/job/script.sh " + jobId;
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            int exitCode = process.waitFor();
            return "Executed job " + jobId + " (Exit code: " + exitCode + ")\
Output:\
" + output.toString();
        } catch (Exception e) {
            return "Error executing job: " + e.getMessage();
        }
    }
}