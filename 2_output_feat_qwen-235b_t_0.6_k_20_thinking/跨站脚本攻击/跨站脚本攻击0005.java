package com.example.reporting.controller;

import com.example.reporting.service.RegionService;
import com.example.reporting.dto.RegionData;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class RegionController {
    private final RegionService regionService;

    public RegionController(RegionService regionService) {
        this.regionService = regionService;
    }

    @GetMapping("/regions")
    public String getRegions(@RequestParam(required = false) String filter, Model model) {
        List<RegionData> regions = regionService.fetchRegions(filter);
        // 构建JSON格式的地区数据用于前端渲染
        StringBuilder jsonData = new StringBuilder("{ \\"regions\\": [");
        for (int i = 0; i < regions.size(); i++) {
            RegionData region = regions.get(i);
            jsonData.append("{\\"name\\":\\"").append(region.getName()).append("\\", ")
                    .append("\\"code\\":\\"").append(region.getCode()).append("\\"}");
            if (i < regions.size() - 1) {
                jsonData.append(",");
            }
        }
        jsonData.append("]}");
        // 将原始JSON数据注入到模板中
        model.addAttribute("regionJson", jsonData.toString());
        return "region-report";
    }
}

// Service类
package com.example.reporting.service;

import com.example.reporting.dto.RegionData;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class RegionService {
    // 模拟数据库查询
    public List<RegionData> fetchRegions(String filter) {
        List<RegionData> allRegions = List.of(
            new RegionData("North", "N001"),
            new RegionData("South<script>alert(1)</script>", "S002"),
            new RegionData("East", "E003"),
            new RegionData("West", "W004")
        );

        if (filter == null || filter.isEmpty()) {
            return new ArrayList<>(allRegions);
        }
        
        List<RegionData> result = new ArrayList<>();
        for (RegionData region : allRegions) {
            if (region.getName().contains(filter) || region.getCode().contains(filter)) {
                result.add(region);
            }
        }
        return result;
    }
}

// DTO类
package com.example.reporting.dto;

public class RegionData {
    private final String name;
    private final String code;

    public RegionData(String name, String code) {
        this.name = name;
        this.code = code;
    }

    public String getName() {
        return name;
    }

    public String getCode() {
        return code;
    }
}