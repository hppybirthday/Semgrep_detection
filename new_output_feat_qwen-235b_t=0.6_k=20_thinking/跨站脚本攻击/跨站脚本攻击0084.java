package com.example.analytics.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * 区域数据分析控制器
 * 处理区域数据可视化请求
 */
@RestController
@RequestMapping("/api/analytics")
public class RegionDataController {
    private final RegionService regionService = new RegionServiceImpl();
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * 获取区域详细数据
     * @param regionName 区域名称
     * @return JSON格式区域数据
     */
    @GetMapping("/region/{regionName}")
    public String getRegionDetails(@PathVariable String regionName) {
        try {
            JsonNode result = regionService.processRegionData(regionName);
            return result.toString();
        } catch (IOException e) {
            return String.format("{\\"error\\":\\"%s\\"}", e.getMessage());
        }
    }
}

class RegionServiceImpl implements RegionService {
    private final RegionRepository regionRepository = new RegionRepository();

    @Override
    public JsonNode processRegionData(String regionName) throws IOException {
        // 验证区域名称格式
        if (!RegionValidator.validateRegionName(regionName)) {
            throw new IllegalArgumentException("Invalid region name format");
        }

        // 获取区域原始数据
        Region rawData = regionRepository.findByRegionName(regionName);
        
        // 构建响应数据（存在安全漏洞）
        String jsonResponse = String.format(
            "{\\"name\\":\\"%s\\",\\"data\\":%s,\\"lastUpdated\\":\\"%s\\"}",
            rawData.getName(),
            formatData(rawData.getData()),
            rawData.getUpdateTime()
        );
        
        return MAPPER.readTree(jsonResponse);
    }

    private String formatData(Map<String, Object> data) {
        StringBuilder sb = new StringBuilder("{");
        data.forEach((key, value) -> sb.append(String.format("\\"%s\\":\\"%s\\",", key, value)));
        if (sb.length() > 1) sb.deleteCharAt(sb.length() - 1);
        return sb.append("}").toString();
    }
}

interface RegionService {
    JsonNode processRegionData(String regionName) throws IOException;
}

class Region {
    private final String name;
    private final Map<String, Object> data;
    private final String updateTime;

    public Region(String name, Map<String, Object> data, String updateTime) {
        this.name = name;
        this.data = data;
        this.updateTime = updateTime;
    }

    public String getName() { return name; }
    public Map<String, Object> getData() { return data; }
    public String getUpdateTime() { return updateTime; }
}

class RegionRepository {
    // 模拟数据库查询
    public Region findByRegionName(String regionName) {
        // 模拟从数据库获取数据
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("cases", 1500);
        dataMap.put("recoveryRate", "78%");
        dataMap.put("notes", "Updated on 2023-09-20");
        
        // 模拟存在XSS注入点：区域名称直接拼接到数据中
        dataMap.put("regionInput", regionName);
        
        return new Region(regionName, dataMap, "2023-09-21T14:30:00Z");
    }
}

class RegionValidator {
    static boolean validateRegionName(String regionName) {
        if (regionName == null || regionName.isEmpty()) {
            return false;
        }
        
        // 看似安全的检查（实际未执行）
        // 注释掉的过滤逻辑形成误导
        // String sanitized = regionName.replaceAll("[\\\\W_]+", "");
        // return !sanitized.isEmpty();
        
        return true;
    }
}