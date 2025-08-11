package com.example.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/upload")
public class ExcelUploadController {
    @Autowired
    private ConfigProcessingService configService;

    @PostMapping(path = "/settings", consumes = "multipart/form-data")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            return configService.processConfiguration(file);
        } catch (Exception e) {
            return "Configuration processing failed: " + e.getMessage();
        }
    }
}

@Service
class ConfigProcessingService {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    String processConfiguration(MultipartFile file) throws Exception {
        Path tempFile = Files.createTempFile("upload-", ".xlsx");
        file.transferTo(tempFile);

        try (Workbook workbook = new XSSFWorkbook(tempFile.toFile())) {
            Sheet sheet = workbook.getSheetAt(0);
            Row configRow = sheet.getRow(2);
            Cell jsonCell = configRow.getCell(1);
            
            String configJson = jsonCell.getStringCellValue();
            return ConfigParser.parseAndValidate(configJson);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
}

class ConfigParser {
    static String parseAndValidate(String configJson) throws JsonProcessingException, IOException {
        JsonNode rootNode = new ObjectMapper().readTree(configJson);
        JsonNode authConfig = rootNode.get("SystemSetting").get("AuthProvider");
        
        Map<String, Object> configMap = new ObjectMapper().convertValue(authConfig, Map.class);
        String groupData = (String) configMap.get("GROUP");
        
        if (groupData == null || !groupData.startsWith("B64:")) {
            throw new IllegalArgumentException("Invalid data format");
        }
        
        return processSerializedData(groupData.substring(4));
    }

    private static String processSerializedData(String encodedData) throws IOException, ClassNotFoundException {
        byte[] rawData = Base64.getDecoder().decode(encodedData);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(rawData))) {
            Object configObject = ois.readObject();
            return "Successfully loaded config: " + configObject.getClass().getName();
        }
    }
}

// 依赖项配置：
// implementation 'org.springframework.boot:spring-boot-starter-web'
// implementation 'org.apache.poi:poi-ooxml:5.2.3'
// implementation 'com.fasterxml.jackson.core:jackson-databind:2.13.3'
// implementation 'com.alibaba:fastjson:1.2.83'