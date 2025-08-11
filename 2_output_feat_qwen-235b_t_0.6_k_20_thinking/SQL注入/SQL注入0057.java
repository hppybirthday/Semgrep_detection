package com.example.mathmod.controller;

import com.example.mathmod.service.ModelService;
import com.example.mathmod.common.Result;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 模型管理控制器
 * 提供模型删除接口
 */
@RestController
@RequestMapping("/api/models")
public class ModelController {
    @Autowired
    private ModelService modelService;

    /**
     * 批量删除模型
     * @param ids 模型ID列表（逗号分隔）
     * @return 操作结果
     */
    @DeleteMapping("/delete")
    public Result deleteModels(@RequestParam("ids") String ids) {
        modelService.deleteModels(ids);
        return Result.success("删除成功");
    }
}

package com.example.mathmod.service;

import com.example.mathmod.mapper.ModelMapper;
import com.example.mathmod.model.Model;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 模型服务类
 * 处理模型删除业务逻辑
 */
@Service
public class ModelService {
    @Autowired
    private ModelMapper modelMapper;

    /**
     * 删除指定ID的模型
     * @param ids 模型ID列表（逗号分隔）
     */
    public void deleteModels(String ids) {
        // 构建动态SQL语句
        String sql = buildDeleteSQL(ids);
        modelMapper.batchDelete(sql);
    }

    /**
     * 构建删除SQL语句
     * @param ids 原始ID字符串
     * @return 完整的SQL语句
     */
    private String buildDeleteSQL(String ids) {
        // 验证ID格式（仅允许数字和逗号）
        if (!ids.matches("[\\d,]+")) {
            throw new IllegalArgumentException("ID格式错误");
        }
        return String.format("DELETE FROM math_models WHERE id IN (%s)", ids);
    }
}

package com.example.mathmod.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Param;

/**
 * 模型数据访问接口
 */
public interface ModelMapper extends BaseMapper<Model> {
    /**
     * 执行批量删除操作
     * @param sql 动态构建的SQL语句
     */
    @Delete("${sql}")
    void batchDelete(@Param("sql") String sql);
}