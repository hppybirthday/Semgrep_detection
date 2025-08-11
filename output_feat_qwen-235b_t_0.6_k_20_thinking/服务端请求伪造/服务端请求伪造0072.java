import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.function.*;
import java.util.stream.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.http.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
public class ImageProcessingApp {

    public static void main(String[] args) {
        SpringApplication.run(ImageProcessingApp.class, args);
    }

    @PostMapping("/process")
    public ResponseEntity<String> processImage(@RequestParam String imageUrl) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                URL url = new URL(imageUrl);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                if (conn.getResponseCode() != 200) {
                    return "Failed to download image: " + conn.getResponseCode();
                }

                Path tempFile = Files.createTempFile("image_", ".tmp");
                try (InputStream in = conn.getInputStream();
                     OutputStream out = Files.newOutputStream(tempFile)) {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        out.write(buffer, 0, bytesRead);
                    }
                }

                // Simulate ML processing and upload to storage
                String storagePath = "/secure_storage/" + tempFile.getFileName();
                Files.move(tempFile, Paths.get(storagePath));
                return "Image processed and stored at: " + storagePath;

            } catch (Exception e) {
                // In real app, proper error handling would be implemented
                e.printStackTrace();
                return "Error processing image";
            }
        }).thenApply(ResponseEntity::ok)
        .exceptionally(ex -> ResponseEntity.status(500).body("Internal error"))
        .join();
    }
}