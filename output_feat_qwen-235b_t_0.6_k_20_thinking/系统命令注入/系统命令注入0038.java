import java.io.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class DeviceController {
    @PostMapping("/upload")
    public String uploadData(@RequestBody Map<String, String> payload) {
        try {
            String deviceId = payload.get("id");
            String command = "ping -c 1 " + deviceId;
            Process process = Runtime.getRuntime().exec(command);
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
            return "Error: " + e.getMessage();
        }
    }
}