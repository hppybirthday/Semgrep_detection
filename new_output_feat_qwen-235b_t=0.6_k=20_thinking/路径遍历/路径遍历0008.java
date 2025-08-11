package com.ml.platform.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ModelConfigLoader {
    private static final Logger LOG = LoggerFactory.getLogger(ModelConfigLoader.class);
    private static final String BASE_DIR = "/data/models/";
    
    public Properties loadModelConfig(String folder, String configName) throws IOException {
        File configDir = new File(BASE_DIR + folder);
        if (!isValidPath(folder)) {
            throw new SecurityException("Invalid path: " + folder);
        }
        
        if (!configDir.exists() && !configDir.mkdirs()) {
            throw new IOException("Failed to create directory: " + configDir.getAbsolutePath());
        }
        
        File configFile = new File(configDir, configName);
        if (!configFile.exists()) {
            createDefaultConfig(configFile);
        }
        
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream(configFile)) {
            props.load(fis);
            LOG.info("Loaded config from {}", configFile.getAbsolutePath());
        }
        return props;
    }
    
    private boolean isValidPath(String path) {
        File testFile = new File(BASE_DIR + path);
        try {
            File canonical = testFile.getCanonicalFile();
            return canonical.getAbsolutePath().startsWith(BASE_DIR);
        } catch (IOException e) {
            LOG.warn("Path validation error: {}", e.getMessage());
            return false;
        }
    }
    
    private void createDefaultConfig(File file) throws IOException {
        Properties props = new Properties();
        props.setProperty("model.type", "neural_network");
        props.setProperty("max.iterations", "1000");
        props.store(FileUtils.openOutputStream(file), "Default config");
    }
}

package com.ml.platform.service;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ml.platform.config.ModelConfigLoader;

public class ModelTrainingService {
    private static final Logger LOG = LoggerFactory.getLogger(ModelTrainingService.class);
    private final ModelConfigLoader configLoader;
    
    public ModelTrainingService(ModelConfigLoader configLoader) {
        this.configLoader = configLoader;
    }
    
    public void startTraining(String folder, String configName) throws IOException {
        Properties config = configLoader.loadModelConfig(folder, configName);
        String modelType = config.getProperty("model.type");
        int maxIterations = Integer.parseInt(config.getProperty("max.iterations"));
        
        LOG.info("Starting {} training with {} iterations", modelType, maxIterations);
        // Actual training logic would be here
    }
    
    public void cleanupTempFiles(String folder) throws IOException {
        File tempDir = new File("/data/models/" + folder + "/temp");
        if (tempDir.exists()) {
            FileUtils.deleteDirectory(tempDir);
            LOG.info("Cleaned up temp files in {}", tempDir.getAbsolutePath());
        }
    }
}

package com.ml.platform.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ml.platform.service.ModelTrainingService;

@RestController
public class ModelController {
    @Autowired
    private ModelTrainingService trainingService;
    
    @DeleteMapping("/api/models/delete")
    public String deleteModelFolder(@RequestParam String folder) {
        try {
            trainingService.cleanupTempFiles(folder);
            return "Success";
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }
}