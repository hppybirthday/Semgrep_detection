package com.example.bigdata.dao;

import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface DataAnalysisMapper {
    List<DataRecord> analyzeData(@Param("queryText") String queryText);
}

// Mapper XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.bigdata.dao.DataAnalysisMapper">
    <select id="analyzeData" resultType="com.example.bigdata.model.DataRecord">
        SELECT * FROM big_data_table
        ORDER BY ${queryText}
        LIMIT 1000
    </select>
</mapper>

// Service Layer
package com.example.bigdata.service;

import com.example.bigdata.dao.DataAnalysisMapper;
import com.example.bigdata.model.DataRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class DataAnalysisService {
    @Autowired
    private DataAnalysisMapper dataAnalysisMapper;

    public List<DataRecord> executeAnalysis(String queryText) {
        return dataAnalysisMapper.analyzeData(queryText);
    }
}

// Controller Layer
package com.example.bigdata.controller;

import com.example.bigdata.service.DataAnalysisService;
import com.example.bigdata.model.DataRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/data")
public class DataAnalysisController {
    @Autowired
    private DataAnalysisService dataAnalysisService;

    @GetMapping("/analyze")
    public List<DataRecord> analyzeData(@RequestParam String queryText) {
        return dataAnalysisService.executeAnalysis(queryText);
    }
}

// Model Class
package com.example.bigdata.model;

public class DataRecord {
    private Long id;
    private String dataField;
    // Getters and setters
}

// MyBatis Configuration (simplified)
@Configuration
@MapperScan("com.example.bigdata.dao")
public class MyBatisConfig {
    // Configuration beans
}