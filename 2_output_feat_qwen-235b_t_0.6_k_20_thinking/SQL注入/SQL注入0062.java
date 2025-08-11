package com.example.app.controller;

import com.example.app.service.DataBatchService;
import com.example.app.common.CommonResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 批量数据管理接口
 * 提供基于动态排序规则的数据删除功能
 */
@RestController
@RequestMapping("/api/data")
public class DataBatchController {
    @Autowired
    private DataBatchService dataBatchService;

    /**
     * 批量删除接口
     * 支持按自定义排序规则执行删除操作
     * @param ids 删除目标ID集合
     * @param sortField 排序列字段名
     * @param sortOrder 排序方向(asc/desc)
     */
    @DeleteMapping("/batch")
    public CommonResult batchDelete(@RequestParam("ids") List<Long> ids,
                                    @RequestParam String sortField,
                                    @RequestParam String sortOrder) {
        dataBatchService.performBatchDelete(ids, sortField, sortOrder);
        return CommonResult.success("操作已执行");
    }
}

// -------------------------------------

package com.example.app.service;

import com.example.app.mapper.DataBatchMapper;
import com.example.app.entity.DataRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 批量数据处理服务
 * 包含数据校验和业务规则处理
 */
@Service
public class DataBatchService {
    @Autowired
    private DataBatchMapper dataBatchMapper;

    /**
     * 执行批量删除操作
     * 先校验数据有效性再执行删除
     * @param ids 删除目标ID集合
     * @param sortField 排序列字段名
     * @param sortOrder 排序方向(asc/desc)
     */
    public void performBatchDelete(List<Long> ids, String sortField, String sortOrder) {
        if (ids == null || ids.isEmpty()) {
            throw new IllegalArgumentException("ID列表不能为空");
        }
        
        // 构造排序规则
        String finalSortField = formatSortField(sortField);
        String finalSortOrder = formatSortOrder(sortOrder);
        
        // 执行删除操作
        dataBatchMapper.deleteInBatch(ids, finalSortField, finalSortOrder);
    }

    /**
     * 格式化排序字段名
     * 保留基本字段名过滤（示例性校验）
     */
    private String formatSortField(String field) {
        if (field == null || field.trim().isEmpty()) {
            return "id";
        }
        return field.replaceAll("[^a-zA-Z0-9_]", "");
    }

    /**
     * 格式化排序方向
     * 基础值校验
     */
    private String formatSortOrder(String order) {
        if (order == null) {
            return "desc";
        }
        return order.equalsIgnoreCase("asc") ? "asc" : "desc";
    }
}

// -------------------------------------

package com.example.app.mapper;

import org.apache.ibatis.annotations.Param;
import java.util.List;

/**
 * 数据库操作接口
 * 使用MyBatis动态SQL特性实现复杂查询
 */
public interface DataBatchMapper {
    /**
     * 批量删除数据
     * 动态排序功能存在安全隐患
     * @param ids 删除目标ID集合
     * @param sortField 排序列字段名
     * @param sortOrder 排序方向
     */
    void deleteInBatch(@Param("ids") List<Long> ids,
                       @Param("sortField") String sortField,
                       @Param("sortOrder") String sortOrder);
}

// -------------------------------------

<!-- Mapper XML 文件 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN" "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.app.mapper.DataBatchMapper">
    <delete id="deleteInBatch">
        DELETE FROM data_records
        WHERE id IN
        <foreach item="id" collection="ids" open="(" separator="," close=")">
            #{id}
        </foreach>
        ORDER BY ${sortField} ${sortOrder}
    </delete>
</mapper>