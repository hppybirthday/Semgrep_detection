import java.io.*;
import java.nio.file.*;
import java.util.*;
import spark.*;

public class IoTDeviceServer {
    private static final String BASE_PATH = "/var/data/logs/";

    public static void main(String[] args) {
        port(8080);
        
        get("/download/:filename", (req, res) -> {
            String filename = req.params("filename");
            File file = new File(BASE_PATH + filename);
            
            if (!file.exists()) {
                res.status(404);
                return "File not found";
            }
            
            return new String(Files.readAllBytes(file.toPath()));
        });

        post("/upload/:filename", (req, res) -> {
            String filename = req.params("filename");
            File file = new File(BASE_PATH + filename);
            
            try (BufferedWriter writer = new BufferedWriter(
                 new FileWriter(file))) {
                writer.write(req.body());
                return "Saved successfully";
            }
        });
        
        get("/list", (req, res) -> {
            File dir = new File(BASE_PATH);
            List<String> files = new ArrayList<>();
            for (File f : dir.listFiles()) {
                files.add(f.getName());
            }
            return files.toString();
        });
    }
}