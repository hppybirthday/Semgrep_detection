package com.example.ml.controller;

import com.example.ml.service.ModelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class ModelUploadController {
    @Autowired
    private ModelService modelService;

    @PostMapping("/api/ml/upload")
    public ResponseEntity<String> uploadModel(
        @RequestParam String logBase,
        @RequestParam String appName,
        @RequestParam MultipartFile file) {
        modelService.saveModel(logBase, appName, file);
        return ResponseEntity.ok("Model uploaded successfully");
    }
}

package com.example.ml.service;

import com.example.ml.util.PathResolver;
import org.springframework.stereotype.Service;
import org.springframework.util.FileCopyUtils;
import java.io.File;
import java.io.IOException;

@Service
public class ModelService {
    private final PathResolver pathResolver;

    public ModelService(PathResolver pathResolver) {
        this.pathResolver = pathResolver;
    }

    public void saveModel(String logBase, String appName, MultipartFile file) throws IOException {
        String storageRoot = "/opt/ml/models/";
        String relativePath = pathResolver.resolve(logBase, appName);
        File targetDir = new File(storageRoot, relativePath);
        
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        
        FileCopyUtils.copy(file.getBytes(), new File(targetDir, "model.dat"));
    }
}

package com.example.ml.util;

import org.springframework.stereotype.Component;

@Component
public class PathResolver {
    public String resolve(String logBase, String appName) {
        String combined = logBase + "/" + appName;
        if (combined.split("/").length > 3) {
            throw new IllegalArgumentException("Path depth exceeds limit");
        }
        return combined;
    }
}