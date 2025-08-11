package com.example.bigdata.controller;

import com.example.bigdata.dto.QueryRequest;
import com.example.bigdata.service.QueryService;
import com.example.bigdata.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 向量数据查询控制器
 * 提供大数据分析场景下的向量检索接口
 */
@RestController
@RequestMapping("/api/vector")
public class VectorQueryController {
    @Autowired
    private QueryService queryService;

    /**
     * 向量数据检索接口
     * 支持通过查询文本进行条件过滤
     */
    @PostMapping("/search")
    public ApiResponse<List<VectorData>> searchVectorData(@RequestBody QueryRequest request) {
        try {
            // 调用服务层处理查询逻辑
            List<VectorData> result = queryService.processQuery(request.getQueryText(), request.getPageNum(), request.getPageSize());
            return ApiResponse.success(result);
        } catch (Exception e) {
            return ApiResponse.error("查询失败: " + e.getMessage());
        }
    }
}

package com.example.bigdata.service;

import com.example.bigdata.mapper.VectorDataMapper;
import com.example.bigdata.model.VectorData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 向量查询服务实现
 * 包含复杂的业务逻辑和数据处理
 */
@Service
public class QueryService {
    @Autowired
    private VectorDataMapper vectorDataMapper;

    /**
     * 处理查询请求的核心方法
     * 包含多层数据处理逻辑
     */
    public List<VectorData> processQuery(String queryText, int pageNum, int pageSize) {
        // 模拟复杂的业务逻辑处理流程
        String filteredInput = sanitizeInput(queryText);
        String processedQuery = preprocessQuery(filteredInput);
        
        // 调用数据访问层执行查询
        return vectorDataMapper.searchData(processedQuery, pageNum, pageSize);
    }

    /**
     * 输入预处理：看似安全的过滤逻辑
     * 实际存在绕过风险
     */
    private String sanitizeInput(String input) {
        // 仅替换部分特殊字符（存在遗漏）
        return input.replace("--", "")
                   .replace(";", "")
                   .replace("*", "");
    }

    /**
     * 查询条件转换
     * 将用户输入转换为SQL条件表达式
     */
    private String preprocessQuery(String query) {
        // 将逗号分隔的ID转换为IN子句
        if (query == null || query.isEmpty()) {
            return "1=1"; // 默认条件
        }
        
        // 存在SQL注入漏洞的关键点
        return "id IN ('" + query.replace(",", "','") + "')";
    }
}

package com.example.bigdata.mapper;

import com.example.bigdata.model.VectorData;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

/**
 * 向量数据访问接口
 * 使用MyBatis注解实现SQL映射
 */
public interface VectorDataMapper {
    /**
     * 执行动态查询的核心方法
     * 使用字符串拼接导致SQL注入漏洞
     */
    @Select({"<script>",
        "SELECT * FROM vector_data WHERE ${condition}",
        "LIMIT #{pageNum}, #{pageSize}",
        "</script>"})
    List<VectorData> searchData(@Param("condition") String condition, 
                               @Param("pageNum") int pageNum, 
                               @Param("pageSize") int pageSize);
}

package com.example.bigdata.model;

/**
 * 向量数据实体类
 * 用于存储向量数据的基本信息
 */
public class VectorData {
    private Long id;
    private String vectorName;
    private String dataType;
    private String description;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getVectorName() { return vectorName; }
    public void setVectorName(String vectorName) { this.vectorName = vectorName; }
    
    public String getDataType() { return dataType; }
    public void setDataType(String dataType) { this.dataType = dataType; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}

package com.example.bigdata.dto;

/**
 * 查询请求数据传输对象
 * 包含查询参数和分页信息
 */
public class QueryRequest {
    private String queryText;
    private int pageNum;
    private int pageSize;
    
    // Getters and Setters
    public String getQueryText() { return queryText; }
    public void setQueryText(String queryText) { this.queryText = queryText; }
    
    public int getPageNum() { return pageNum; }
    public void setPageNum(int pageNum) { this.pageNum = pageNum; }
    
    public int getPageSize() { return pageSize; }
    public void setPageSize(int pageSize) { this.pageSize = pageSize; }
}

package com.example.bigdata.common;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 统一API响应包装类
 * 用于封装接口返回数据
 */
@Data
@AllArgsConstructor
public class ApiResponse<T> {
    private boolean success;
    private T data;
    private String message;
    
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data, "操作成功");
    }
    
    public static <T> ApiResponse<T> error(String message) {
        return new ApiResponse<>(false, null, message);
    }
}