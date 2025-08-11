import java.io.*;
import java.util.*;
import javax.servlet.*;
import javax.servlet.http.*;
import org.springframework.stereotype.*;

@RestController
public class ModelExecutor {
    @GetMapping("/train")
    public String executeTraining(@RequestParam String user, @RequestParam String password, @RequestParam String db) {
        try {
            List<String> commands = new ArrayList<>();
            commands.add("python");
            commands.add("train_model.py");
            commands.add("--user");
            commands.add(user);
            commands.add("--password");
            commands.add(password);
            commands.add("--db");
            commands.add(db);
            
            ProcessBuilder pb = new ProcessBuilder(commands);
            Process process = pb.start();
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return "Exit Code: " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

// train_model.py (simplified example)
/*
import sys, subprocess

if "--user" in sys.argv:
    user_index = sys.argv.index("--user") + 1
    password_index = sys.argv.index("--password") + 1
    db_index = sys.argv.index("--db") + 1
    
    user = sys.argv[user_index]
    password = sys.argv[password_index]
    db = sys.argv[db_index]
    
    # Simulate DB connection command
    subprocess.run(["mysql", "-u", user, "-p"+password, db])
*/