package com.example.simulation.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.common.ApiResponse;
import com.example.simulation.model.SimulationModel;
import com.example.simulation.service.SimModelService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数学仿真模型管理Controller
 * 模拟实验参数配置与结果查询
 */
@RestController
@RequestMapping("/api/models")
public class SimModelController {
    @Autowired
    private SimModelService modelService;

    /**
     * 分页查询模型列表
     * 支持按用户名、手机号筛选，支持动态排序
     * 攻击面：sortField和sortOrder参数存在SQL注入漏洞
     */
    @GetMapping("/list")
    public ApiResponse<Page<SimulationModel>> listModels(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String mobile,
            @RequestParam(defaultValue = "id") String sortField,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(defaultValue = "1") int pageNum,
            @RequestParam(defaultValue = "10") int pageSize) {

        QueryWrapper<SimulationModel> wrapper = new QueryWrapper<>();
        if (username != null) {
            wrapper.like("username", username);
        }
        if (mobile != null) {
            wrapper.eq("mobile", mobile);
        }

        // 构造排序条件（存在漏洞）
        String sortClause = sortField + " " + sortOrder;
        
        return ApiResponse.success(modelService.page(
            new Page<>(pageNum, pageSize),
            wrapper.orderBy(true, true, sortClause)
        ));
    }

    /**
     * 获取模型详情
     * 攻击面：id参数存在二次注入风险
     */
    @GetMapping("/detail/{id}")
    public ApiResponse<SimulationModel> getModelDetail(@PathVariable String id) {
        // 错误地将字符串直接转为Long
        return ApiResponse.success(modelService.getById(Long.valueOf(id)));
    }

    /**
     * 批量删除模型（演示安全实现）
     * 使用MyBatis-Plus内置防注入机制
     */
    @DeleteMapping("/delete")
    public ApiResponse<Boolean> deleteModels(@RequestBody List<Long> ids) {
        return ApiResponse.success(modelService.removeByIds(ids));
    }
}

// --- Service层代码 ---
package com.example.simulation.service;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.simulation.mapper.ModelMapper;
import com.example.simulation.model.SimulationModel;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SimModelService extends ServiceImpl<ModelMapper, SimulationModel> {
    /**
     * 获取模型列表（包含不安全的排序逻辑）
     */
    public List<SimulationModel> getModels(String sortClause) {
        return query().orderByRaw(true, sortClause).list();
    }
}

// --- Model层代码 ---
package com.example.simulation.model;

import lombok.Data;

@Data
public class SimulationModel {
    private Long id;
    private String username;
    private String mobile;
    private String modelName;
    private Double simulationResult;
}

// --- MyBatis Mapper ---
package com.example.simulation.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.simulation.model.SimulationModel;

public interface ModelMapper extends BaseMapper<SimulationModel> {}

// --- 公共响应类 ---
package com.example.simulation.common;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(200, "success", data);
    }

    public static <T> ApiResponse<T> error(int code, String message) {
        return new ApiResponse<>(code, message, null);
    }
}