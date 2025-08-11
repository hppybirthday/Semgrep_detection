package com.example.ml.dao;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface TrainingDataDao {
    @Select("SELECT * FROM training_data WHERE id IN (${ids})")
    List<TrainingData> getTrainingData(@Param("ids") String ids);
}

// com/example/ml/service/TrainingService.java
package com.example.ml.service;

import com.example.ml.dao.TrainingDataDao;
import com.example.ml.model.TrainingData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class TrainingService {
    @Autowired
    private TrainingDataDao trainingDataDao;

    public List<TrainingData> getTrainingData(String ids) {
        // 防御式编程误用示例：错误地认为字符串拼接是安全的
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 漏洞点：直接传递原始输入到SQL语句
        return trainingDataDao.getTrainingData(ids);
    }
}

// com/example/ml/controller/TrainingController.java
package com.example.ml.controller;

import com.example.ml.model.ApiResponse;
import com.example.ml.service.TrainingService;
import com.example.ml.model.TrainingData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/training")
public class TrainingController {
    @Autowired
    private TrainingService trainingService;

    @GetMapping("/data")
    public ApiResponse<List<TrainingData>> getTrainingData(@RequestParam String ids) {
        // 防御式编程误用：仅验证非空但未做内容过滤
        if (ids == null || ids.trim().isEmpty()) {
            return new ApiResponse<>(false, "无效的ID输入");
        }
        
        try {
            List<TrainingData> data = trainingService.getTrainingData(ids);
            return new ApiResponse<>(true, data);
        } catch (Exception e) {
            return new ApiResponse<>(false, "数据查询失败: " + e.getMessage());
        }
    }
}

// com/example/ml/model/TrainingData.java
package com.example.ml.model;

public class TrainingData {
    private Long id;
    private String features;
    private Double label;
    // 省略getter/setter
}

// MyBatis XML映射文件（resources/mapper/TrainingDataMapper.xml）
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
  PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
  "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.ml.dao.TrainingDataDao">
  <select id="getTrainingData" resultType="com.example.ml.model.TrainingData">
    SELECT * FROM training_data WHERE id IN (${ids})
  </select>
</mapper>