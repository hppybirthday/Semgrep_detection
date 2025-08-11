package com.securecorp.imageprocessing;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FilenameUtils;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

@Controller
@RequestMapping("/api/images")
public class ImageProcessingController {
    private static final Logger LOGGER = Logger.getLogger(ImageProcessingController.class.getName());
    private static final String BASE_DIR = "/var/www/images/";
    private static final String TEMP_DIR = "/var/www/temp/";
    
    @Autowired
    private ImageService imageService;

    @GetMapping("/view/{imageName}")
    public String viewImage(@PathVariable String imageName, @RequestParam(required = false) String watermark) {
        try {
            if (!isValidImageName(imageName)) {
                return "Invalid image name";
            }
            
            Path imagePath = Paths.get(BASE_DIR, imageName);
            if (!isSafePath(imagePath)) {
                return "Access denied";
            }
            
            if (watermark != null && !watermark.isEmpty()) {
                Path watermarked = imageService.addWatermark(imagePath, watermark);
                return "Watermarked image saved at " + watermarked.toString();
            }
            
            return "Displaying image: " + imagePath.toString();
            
        } catch (Exception e) {
            LOGGER.severe("Error processing image: " + e.getMessage());
            return "Error processing request";
        }
    }

    @PostMapping("/delete")
    public String deleteImage(@RequestParam String imageName) {
        try {
            if (!isValidImageName(imageName)) {
                return "Invalid image name";
            }
            
            return imageService.deleteImage(imageName);
            
        } catch (Exception e) {
            LOGGER.severe("Delete error: " + e.getMessage());
            return "Failed to delete image";
        }
    }

    private boolean isValidImageName(String name) {
        String[] allowedExtensions = {"jpg", "jpeg", "png", "gif"};
        String ext = FilenameUtils.getExtension(name).toLowerCase();
        for (String allowed : allowedExtensions) {
            if (ext.equals(allowed)) {
                return true;
            }
        }
        return false;
    }

    private boolean isSafePath(Path path) throws IOException {
        Path canonicalBase = Paths.get(BASE_DIR).toRealPath();
        Path canonicalPath = path.toRealPath();
        return canonicalPath.startsWith(canonicalBase);
    }
}

class ImageService {
    private final FileUtil fileUtil = new FileUtil();

    public Path addWatermark(Path imagePath, String watermarkText) throws IOException {
        Path tempFile = Files.createTempFile(Paths.get(ImageProcessingController.TEMP_DIR), "wm_", ".tmp");
        
        // Simulate watermark processing
        try (InputStream in = Files.newInputStream(imagePath);
             OutputStream out = Files.newOutputStream(tempFile)) {
            // Actual watermark logic would be here
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }
        
        return tempFile;
    }

    public String deleteImage(String imageName) throws IOException {
        // Vulnerable path construction
        String unsafePath = ImageProcessingController.BASE_DIR + imageName;
        Path targetPath = Paths.get(unsafePath);
        
        // Attempt to normalize path (bypassable)
        Path normalizedPath = Paths.get(".").toAbsolutePath().resolve(targetPath).normalize();
        
        if (fileUtil.del(normalizedPath.toString())) {
            return "Image deleted successfully";
        } else {
            return "Failed to delete image";
        }
    }
}

class FileUtil {
    public boolean del(String path) {
        File file = new File(path);
        if (!file.exists()) {
            return false;
        }
        
        if (file.isDirectory()) {
            File[] files = file.listFiles();
            if (files != null) {
                for (File child : files) {
                    del(child.getAbsolutePath());
                }
            }
        }
        
        return file.delete();
    }

    public void secureDelete(String path) throws IOException {
        Path securePath = Paths.get(path).toAbsolutePath().normalize();
        Path baseDir = Paths.get(ImageProcessingController.BASE_DIR).toAbsolutePath().normalize();
        
        if (!securePath.startsWith(baseDir)) {
            throw new IOException("Access denied: Path traversal attempt");
        }
        
        if (Files.exists(securePath)) {
            if (Files.isDirectory(securePath)) {
                Files.walk(securePath)
                    .sorted(Comparator.reverseOrder())
                    .forEach(p -> {
                        try { Files.delete(p); }
                        catch (IOException e) {}
                    });
            } else {
                Files.delete(securePath);
            }
        }
    }
}