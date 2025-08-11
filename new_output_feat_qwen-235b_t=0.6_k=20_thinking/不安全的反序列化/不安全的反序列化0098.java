package com.example.depot.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;

@Service
@Slf4j
public class DepotProcessingService {
    private static final String CONFIG_SHEET = "ConfigData";
    private static final int MAX_CONFIG_SIZE = 1024 * 1024;

    public void processDepotData(MultipartFile file) throws IOException, ClassNotFoundException {
        try (Workbook workbook = new XSSFWorkbook(file.getInputStream())) {
            Sheet sheet = workbook.getSheet(CONFIG_SHEET);
            if (sheet == null) throw new IOException("Invalid template");

            Row configRow = sheet.getRow(1);
            if (configRow == null) throw new IOException("Empty config row");

            Cell configCell = configRow.getCell(2);
            if (configCell == null) throw new IOException("Missing config cell");

            String encodedData = configCell.getStringCellValue();
            byte[] rawData = Base64.getDecoder().decode(encodedData);
            
            if (rawData.length > MAX_CONFIG_SIZE) {
                throw new IOException("Config size exceeded");
            }

            processSerializedData(rawData);
        }
    }

    private void processSerializedData(byte[] data) throws IOException, ClassNotFoundException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object config = ois.readObject();
            log.info("Loaded config: {}", config.getClass().getName());
            // 模拟配置应用过程
            if (config instanceof DepotConfig) {
                applyDepotConfiguration((DepotConfig) config);
            }
        }
    }

    private void applyDepotConfiguration(DepotConfig config) {
        // 实际业务逻辑
        log.info("Applying depot settings: {}", config.getDepotName());
    }

    // 模拟的配置类
    public static class DepotConfig implements java.io.Serializable {
        private String depotName;
        private int storageLimit;
        // getters/setters
        public String getDepotName() { return depotName; }
        public void setDepotName(String name) { this.depotName = name; }
    }
}

// Controller层
package com.example.depot.controller;

import com.example.depot.service.DepotProcessingService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/depot")
public class DepotUploadController {
    private final DepotProcessingService processingService;

    public DepotUploadController(DepotProcessingService service) {
        this.processingService = service;
    }

    @PostMapping("/add")
    public String addDepot(@RequestParam("file") MultipartFile file) {
        try {
            processingService.processDepotData(file);
            return "Depot added successfully";
        } catch (Exception e) {
            return "Error processing depot: " + e.getMessage();
        }
    }

    @PostMapping("/update")
    public String updateDepot(@RequestParam("file") MultipartFile file) {
        try {
            processingService.processDepotData(file);
            return "Depot updated successfully";
        } catch (Exception e) {
            return "Error updating depot: " + e.getMessage();
        }
    }
}