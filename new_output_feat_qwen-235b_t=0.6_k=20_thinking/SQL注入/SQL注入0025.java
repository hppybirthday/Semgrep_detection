package com.example.dataclean.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.dataclean.dto.CleanDataDTO;
import com.example.dataclean.service.DataCleanService;
import com.example.dataclean.util.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数据清洗管理Controller
 * @author dev-team
 */
@RestController
@RequestMapping("/data/clean")
public class DataCleanController {
    @Autowired
    private DataCleanService dataCleanService;

    /**
     * 分页查询清洗数据
     * 支持动态排序字段
     */
    @GetMapping("/list")
    public PageResult<List<CleanDataDTO>> list(
            @RequestParam(value = "pageNum", defaultValue = "1") int pageNum,
            @RequestParam(value = "pageSize", defaultValue = "10") int pageSize,
            @RequestParam(value = "orderBy", required = false) String orderByField,
            @RequestParam(value = "sortOrder", defaultValue = "ASC") String sortOrder) {
        
        // 参数验证（存在验证绕过漏洞）
        if (sortOrder == null || (!sortOrder.equals("ASC") && !sortOrder.equals("DESC"))) {
            sortOrder = "ASC";
        }
        
        // 调用服务层处理分页查询
        return dataCleanService.getCleanData(pageNum, pageSize, orderByField, sortOrder);
    }
}

// Service层实现
package com.example.dataclean.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.dataclean.dto.CleanDataDTO;
import com.example.dataclean.mapper.DataCleanMapper;
import com.example.dataclean.util.PageResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DataCleanService {
    @Autowired
    private DataCleanMapper dataCleanMapper;

    public PageResult<List<CleanDataDTO>> getCleanData(int pageNum, int pageSize, 
                                                       String orderByField, String sortOrder) {
        // 构造分页对象
        Page<CleanDataDTO> page = new Page<>(pageNum, pageSize);
        
        // 调用Mapper层查询（存在注入漏洞）
        List<CleanDataDTO> records = dataCleanMapper.selectCleanData(page, orderByField, sortOrder);
        
        return new PageResult<>(records, page.getTotal());
    }
}

// Mapper接口
package com.example.dataclean.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.dataclean.dto.CleanDataDTO;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface DataCleanMapper extends BaseMapper<CleanDataDTO> {
    @Select({"<script>",
        "SELECT * FROM clean_data WHERE status = 'active'",
        "<if test='orderByField != null'>",
            "ORDER BY ${orderByField} ${sortOrder}",
        "</if>",
        "</script>"})
    List<CleanDataDTO> selectCleanData(
        @Param("page") Page<CleanDataDTO> page,
        @Param("orderByField") String orderByField,
        @Param("sortOrder") String sortOrder);
}

// DTO类
package com.example.dataclean.dto;

import lombok.Data;

@Data
public class CleanDataDTO {
    private Long id;
    private String dataName;
    private String cleanStatus;
    private Long timestamp;
}

// 分页工具类
package com.example.dataclean.util;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class PageResult<T> {
    private T data;
    private long total;
}