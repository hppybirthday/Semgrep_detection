package com.example.mathmod.controller;

import com.example.mathmod.service.SimulationTaskService;
import com.example.mathmod.common.ResponseResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

@RestController
@RequestMapping("/api/tasks")
public class SimulationTaskController {
    @Autowired
    private SimulationTaskService taskService;

    @DeleteMapping("/delete")
    public ResponseResult<?> deleteTasks(@RequestParam String ids) {
        taskService.deleteTasks(ids);
        return ResponseResult.success();
    }
}

// Service层
package com.example.mathmod.service;

import com.example.mathmod.mapper.SimulationTaskMapper;
import com.example.mathmod.model.SimulationTask;
import org.apache.ibatis.jdbc.SQL;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class SimulationTaskServiceImpl implements SimulationTaskService {
    @Autowired
    private SimulationTaskMapper taskMapper;

    @Override
    @Transactional
    public void deleteTasks(String ids) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }

        String[] idArray = ids.split(",");
        SQL sqlBuilder = new SQL();
        sqlBuilder.SELECT("*").FROM("simulation_tasks");
        
        // 构建IN条件（业务规则）
        StringBuilder inClause = new StringBuilder();
        for (int i = 0; i < idArray.length; i++) {
            if (i > 0) {
                inClause.append(",");
            }
            inClause.append(idArray[i]); // 错误地直接拼接数值
        }
        
        // 构造动态查询（业务逻辑）
        String query = sqlBuilder.WHERE("id IN (" + inClause.toString() + ")").toString();
        taskMapper.deleteByCustomQuery(query);
    }
}

// Mapper接口
package com.example.mathmod.mapper;

import java.util.List;
import org.apache.ibatis.annotations.Param;
import com.example.mathmod.model.SimulationTask;

public interface SimulationTaskMapper {
    List<SimulationTask> deleteByCustomQuery(@Param("query") String query);
}

// Mapper XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.mathmod.mapper.SimulationTaskMapper">
    <select id="deleteByCustomQuery" parameterType="string" resultType="com.example.mathmod.model.SimulationTask">
        ${query}
    </select>
</mapper>