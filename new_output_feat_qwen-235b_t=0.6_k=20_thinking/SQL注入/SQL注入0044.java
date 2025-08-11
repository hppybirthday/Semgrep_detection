package com.example.simulation.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.model.SimulationResult;
import com.example.simulation.service.SimulationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/simulations")
public class SimulationController {
    @Autowired
    private SimulationService simulationService;

    @GetMapping("/results")
    public Page<SimulationResult> getSimulationResults(
            @RequestParam(value = "keyword", required = false) String keyword,
            @RequestParam(value = "sortField", defaultValue = "id") String sortField,
            @RequestParam(value = "sortOrder", defaultValue = "asc") String sortOrder,
            @RequestParam(value = "page", defaultValue = "1") int pageNum,
            @RequestParam(value = "size", defaultValue = "10") int pageSize) {
        
        // 构造查询条件
        QueryWrapper<SimulationResult> wrapper = new QueryWrapper<>();
        if (keyword != null && !keyword.trim().isEmpty()) {
            wrapper.like("name", keyword);
        }
        
        // 构造排序条件（存在漏洞的关键点）
        if (sortField != null && !sortField.trim().isEmpty()) {
            String orderByClause = sortField + " " + sortOrder;
            wrapper.orderBy(StringUtils.isNotBlank(orderByClause), orderByClause);
        }
        
        return simulationService.getSimulationResults(wrapper, pageNum, pageSize);
    }
}

// Service层代码
package com.example.simulation.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.simulation.mapper.SimulationMapper;
import com.example.simulation.model.SimulationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SimulationService {
    @Autowired
    private SimulationMapper simulationMapper;

    public Page<SimulationResult> getSimulationResults(QueryWrapper<SimulationResult> wrapper, int pageNum, int pageSize) {
        Page<SimulationResult> page = new Page<>(pageNum, pageSize);
        return simulationMapper.selectPage(page, wrapper);
    }
}

// Mapper层接口
package com.example.simulation.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.model.SimulationResult;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import java.util.List;

public interface SimulationMapper extends BaseMapper<SimulationResult> {
    @Select({"<script>",
      "SELECT * FROM simulation_results WHERE 1=1",
      "<if test='ew != null'>",
        "<if test='ew.entity.keyword != null'> AND name LIKE CONCAT('%',#{ew.entity.keyword},'%') </if>",
        "<if test='ew != null and ew.sqlSegment != null and !ew.sqlSegment.isEmpty()'>",
          "ORDER BY ${ew.sqlSegment}",
        "</if>",
      "</if>",
      "</script>"})
    Page<SimulationResult> selectPageCustom(Page<SimulationResult> page, @Param("ew") QueryWrapper<SimulationResult> wrapper);
}

// 实体类
package com.example.simulation.model;

import lombok.Data;

@Data
public class SimulationResult {
    private Long id;
    private String name;
    private String parameters;
    private String resultData;
    private Integer status;
}

// 工具类（存在误导性代码）
package com.example.simulation.util;

import org.apache.commons.lang3.StringUtils;

public class SqlValidator {
    // 看似进行SQL校验，但实际未被调用
    public static boolean isValidColumnName(String columnName) {
        return columnName.matches("^[a-zA-Z0-9_]+$");
    }

    public static String sanitizeOrderClause(String orderClause) {
        // 错误的清理逻辑：仅移除分号但保留其他恶意内容
        return orderClause.replace(";", "");
    }
}