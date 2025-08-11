import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.*;
import org.apache.http.impl.client.*;

@RestController
@RequestMapping("/attachments")
public class AttachmentController {
    private final AttachmentService attachmentService = new AttachmentService();

    @PostMapping("/upload-from-url")
    public String uploadFromUrl(@RequestBody Map<String, String> payload) {
        String fileUrl = payload.get("url");
        String fileName = payload.get("filename");
        
        try {
            return attachmentService.uploadFileFromUrl(fileUrl, fileName);
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

class AttachmentService {
    private final FileStorage storage = new FileStorage();

    public String uploadFileFromUrl(String fileUrl, String filename) throws IOException {
        byte[] fileData = DownloadUtil.downloadFile(fileUrl);
        
        if (fileData.length > 10 * 1024 * 1024) {
            throw new IOException("File too large");
        }
        
        storage.saveFile(filename, fileData);
        return "Uploaded: " + filename;
    }
}

class FileStorage {
    public void saveFile(String filename, byte[] data) throws IOException {
        Path path = Paths.get("/var/uploads/" + filename);
        Files.write(path, data);
    }
}

class DownloadUtil {
    public static byte[] downloadFile(String fileUrl) throws IOException {
        URL url = new URL(fileUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        
        if (connection.getResponseCode() != 200) {
            throw new IOException("Download failed");
        }
        
        try (InputStream input = connection.getInputStream()) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int bytesRead;
            
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
            
            return output.toByteArray();
        }
    }
}