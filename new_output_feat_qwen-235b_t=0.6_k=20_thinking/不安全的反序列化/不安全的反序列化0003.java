package com.example.ecommerce.controller;

import com.example.ecommerce.service.ProductImportService;
import com.example.ecommerce.utils.JsonUtils;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/import")
public class ProductImportController {
    private final ProductImportService productImportService;

    public ProductImportController(ProductImportService productImportService) {
        this.productImportService = productImportService;
    }

    @PostMapping("/products")
    public String importProducts(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return "File is empty";
        }

        try (Workbook workbook = new XSSFWorkbook(file.getInputStream())) {
            Sheet sheet = workbook.getSheetAt(0);
            for (Row row : sheet) {
                if (row.getRowNum() == 0) continue; // Skip header

                Cell categoryCell = row.getCell(2);
                String rawCategories = categoryCell.getStringCellValue();
                
                // Vulnerable deserialization chain
                List<String> categories = productImportService.calcCategoriesToUpdate(rawCategories);
                
                // Process categories further
                if (categories.size() > 5) {
                    return "Too many categories";
                }
            }
            return "Import successful";
        } catch (Exception e) {
            return "Import failed: " + e.getMessage();
        }
    }
}

package com.example.ecommerce.service;

import com.example.ecommerce.utils.JsonUtils;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductImportService {
    public List<String> calcCategoriesToUpdate(String rawData) {
        // Complex business logic mask
        if (rawData == null || rawData.isEmpty()) {
            return List.of("default");
        }

        // Vulnerable deserialization point
        return JsonUtils.jsonToObject(rawData, List.class);
    }
}

package com.example.ecommerce.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

public class JsonUtils {
    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        // Insecure configuration
        mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL);
    }

    public static <T> T jsonToObject(String json, Class<T> clazz) {
        try {
            return mapper.readValue(json, clazz);
        } catch (Exception e) {
            throw new RuntimeException("JSON parse error", e);
        }
    }

    public static <T> T jsonToList(String json) {
        try {
            return mapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new RuntimeException("JSON parse error", e);
        }
    }
}