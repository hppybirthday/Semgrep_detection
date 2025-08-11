package com.example.secureapp.controller;

import com.example.secureapp.service.ImageDownloadService;
import com.example.secureapp.util.URLValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Controller
@RequestMapping("/image")
public class ImageController {
    @Autowired
    private ImageDownloadService imageDownloadService;

    @GetMapping("/upload")
    public ResponseEntity<String> uploadImage(@RequestParam("uri") String imageUri) {
        try {
            if (!URLValidator.isValidURI(imageUri)) {
                return ResponseEntity.badRequest().body("Invalid image URI");
            }

            String result = imageDownloadService.downloadImage(imageUri);
            return ResponseEntity.ok("Image processed: " + result);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Internal server error");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing image");
        }
    }
}

package com.example.secureapp.service;

import com.example.secureapp.util.NetworkUtil;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URL;
import java.nio.file.*;

@Service
public class ImageDownloadService {
    private static final String STORAGE_PATH = "/var/www/images/";

    public String downloadImage(String imageUri) throws IOException {
        URL url = new URL(imageUri);
        Path targetPath = Paths.get(STORAGE_PATH + extractFileName(url));
        
        if (!Files.exists(targetPath.getParent())) {
            Files.createDirectories(targetPath.getParent());
        }

        try (InputStream in = url.openStream()) {
            Files.copy(in, targetPath, StandardCopyOption.REPLACE_EXISTING);
        }
        
        return targetPath.toString();
    }

    private String extractFileName(URL url) {
        String path = url.getPath();
        return path.substring(path.lastIndexOf('/') + 1);
    }
}

package com.example.secureapp.util;

import java.net.URI;

public class URLValidator {
    public static boolean isValidURI(String uriStr) {
        try {
            URI uri = new URI(uriStr);
            String scheme = uri.getScheme();
            if (scheme == null) return false;
            
            // Allow common image protocols
            return scheme.equalsIgnoreCase("http") || 
                   scheme.equalsIgnoreCase("https") ||
                   scheme.equalsIgnoreCase("ftp");
        } catch (Exception e) {
            return false;
        }
    }
}

package com.example.secureapp.util;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkUtil {
    public static boolean isReachable(String urlString) throws IOException {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("HEAD");
        connection.setConnectTimeout(5000);
        return connection.getResponseCode() == HttpURLConnection.HTTP_OK;
    }
}