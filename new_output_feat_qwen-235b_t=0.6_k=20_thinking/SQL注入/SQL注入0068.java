package com.example.ml.controller;

import com.example.ml.service.ModelTrainingService;
import com.example.ml.dto.TrainingRequest;
import com.example.ml.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/api/v1/training")
public class ModelTrainingController {
    @Autowired
    private ModelTrainingService trainingService;

    @PostMapping
    public ApiResponse<String> trainModel(@RequestBody TrainingRequest request) {
        if (request.getClients() == null || request.getClients().length == 0) {
            return ApiResponse.error("Client list cannot be empty");
        }
        
        // 漏洞点：未验证客户端ID格式，直接传递给服务层
        return trainingService.executeTraining(
            Arrays.asList(request.getClients()),
            request.getModelType()
        );
    }
}

package com.example.ml.service;

import com.example.ml.mapper.TrainingRecordMapper;
import com.example.ml.common.ApiResponse;
import com.example.ml.dto.TrainingResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelTrainingService {
    @Autowired
    private TrainingRecordMapper recordMapper;

    public ApiResponse<String> executeTraining(List<String> clients, String modelType) {
        if (clients.size() > 100) {
            return ApiResponse.error("Too many clients specified");
        }

        // 漏洞链：将客户端列表转换为逗号分隔字符串
        String clientList = String.join(",", clients);
        
        // 调用MyBatis动态SQL方法
        if (recordMapper.insertTrainingRecord(clientList, modelType) > 0) {
            return ApiResponse.success("Training started successfully");
        }
        return ApiResponse.error("Failed to start training");
    }
}

package com.example.ml.mapper;

import org.apache.ibatis.annotations.*;
import java.util.List;

public interface TrainingRecordMapper {
    @Select("SELECT * FROM training_records WHERE status = #{status}")
    List<TrainingRecord> selectByStatus(String status);

    // 漏洞点：使用字符串拼接构造IN子句
    @Insert({"<script>",
        "INSERT INTO training_records (clients, model_type) VALUES",
        "<foreach collection='clientList' item='client' open='(' separator=',' close=')'>",
        "#{client}",
        "</foreach>",
        ", #{modelType}",
        "</script>"})
    @Options(useGeneratedKeys = true, keyProperty = "id")
    int insertTrainingRecord(String clientList, String modelType);
}

// MyBatis XML映射文件（resources/mapper/TrainingRecordMapper.xml）
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.ml.mapper.TrainingRecordMapper">
    <insert id="insertTrainingRecord">
        INSERT INTO training_records (clients, model_type)
        VALUES (
            <!-- 漏洞点：直接拼接客户端列表字符串 -->
            '${clientList}',
            #{modelType}
        )
    </insert>
</mapper>