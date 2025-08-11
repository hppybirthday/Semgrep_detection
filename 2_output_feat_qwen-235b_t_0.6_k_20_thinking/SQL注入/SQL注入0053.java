package com.example.ml.controller;

import com.example.ml.service.MachineLearningService;
import com.example.ml.model.DataRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/data")
public class MachineLearningDataController {
    @Autowired
    private MachineLearningService machineLearningService;

    @GetMapping("/list")
    public List<DataRecord> listData(@RequestParam String sortField, @RequestParam String sortOrder) {
        return machineLearningService.getDataList(sortField, sortOrder);
    }
}

// Service层
package com.example.ml.service;

import com.example.ml.mapper.DataRecordMapper;
import com.example.ml.model.DataRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class MachineLearningService {
    @Autowired
    private DataRecordMapper dataRecordMapper;

    public List<DataRecord> getDataList(String sortField, String sortOrder) {
        if (!isValidSortField(sortField)) {
            throw new IllegalArgumentException("Invalid sort field");
        }
        String sortClause = buildSortClause(sortField, sortOrder);
        return dataRecordMapper.selectData(sortClause);
    }

    private boolean isValidSortField(String field) {
        return Arrays.asList("feature1", "feature2", "score").contains(field);
    }

    private String buildSortClause(String field, String order) {
        String normalizedOrder = "DESC".equalsIgnoreCase(order) ? "DESC" : "ASC";
        return field + " " + normalizedOrder;
    }
}

// Mapper接口
package com.example.ml.mapper;

import com.example.ml.model.DataRecord;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface DataRecordMapper {
    List<DataRecord> selectData(@Param("sortClause") String sortClause);
}

// MyBatis XML映射
<!-- DataRecordMapper.xml -->
<select id="selectData" resultType="com.example.ml.model.DataRecord">
    SELECT * FROM data_records
    <if test="sortClause != null">
        ORDER BY ${sortClause}
    </if>
</select>