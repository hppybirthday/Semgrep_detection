import static spark.Spark.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

public class CRMReportService {
    private static final String BASE_DIR = "/var/crm_reports/";
    private static final Gson gson = new Gson();

    public static void main(String[] args) {
        port(8080);
        
        post("/generate-report", (req, res) -> {
            try {
                Map<String, String> payload = gson.fromJson(req.body(), Map.class);
                String outputDir = payload.get("outputDir");
                String reportContent = payload.get("content");
                
                // 漏洞点：直接拼接用户输入到文件路径
                Path targetDir = Paths.get(BASE_DIR + outputDir);
                
                if (!Files.exists(targetDir)) {
                    Files.createDirectories(targetDir);
                }
                
                Path reportFile = targetDir.resolve("customer_report.txt");
                Files.write(reportFile, reportContent.getBytes());
                
                return Map.of("status", "success", "path", reportFile.toString());
                
            } catch (Exception e) {
                res.status(500);
                return Map.of("status", "error", "message", e.getMessage());
            }
        }, gson::toJson);
        
        // 模拟敏感文件存在
        before((req, res) -> {
            Path sensitiveFile = Paths.get("/etc/passwd");
            if (!Files.exists(sensitiveFile)) {
                try {
                    Files.createFile(sensitiveFile);
                } catch (Exception ignored) {}
            }
        });
    }
}