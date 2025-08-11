package com.example.mathmodelling.controller;

import com.example.mathmodelling.service.ModelService;
import com.example.mathmodelling.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数学模型管理Controller
 */
@RestController
@RequestMapping("/api/models")
public class ModelController {
    @Autowired
    private ModelService modelService;

    @DeleteMapping("/batch")
    public Result<?> batchDelete(@RequestParam("ids") List<String> ids) {
        try {
            modelService.deleteModels(ids);
            return Result.success("删除成功");
        } catch (Exception e) {
            return Result.error("删除失败: " + e.getMessage());
        }
    }
}

package com.example.mathmodelling.service;

import com.example.mathmodelling.mapper.ModelMapper;
import com.example.mathmodelling.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ModelServiceImpl implements ModelService {
    @Autowired
    private ModelMapper modelMapper;

    private boolean validateIds(List<String> ids) {
        // 校验ID格式（业务规则）
        return ids.stream().allMatch(id -> id.matches("\\\\d+"));
    }

    private String convertToIdString(List<String> ids) {
        // 转换为逗号分隔字符串（业务逻辑）
        return String.join(",", ids);
    }

    @Override
    public void deleteModels(List<String> ids) {
        if (!validateIds(ids)) {
            throw new IllegalArgumentException("ID格式错误");
        }
        
        String idList = convertToIdString(ids);
        modelMapper.deleteModels(idList);
    }
}

package com.example.mathmodelling.mapper;

import org.beetl.sql.mapper.Mapper;
import org.beetl.sql.mapper.annotation.SqlResource;
import org.springframework.stereotype.Repository;

@Repository
@SqlResource("model")
public interface ModelMapper extends Mapper {
    void deleteModels(String ids);
}

// resources/sql/model.sql
<!--<?xml version="1.0" encoding="UTF-8" ?>-->
<sql xmlns="http://beetl.com/sql">
    <delete id="deleteModels">
        DELETE FROM math_models WHERE id IN ( ${ids} )
    </delete>
</sql>