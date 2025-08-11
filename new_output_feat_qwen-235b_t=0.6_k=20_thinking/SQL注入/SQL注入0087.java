package com.example.simulation.controller;

import com.example.simulation.service.SimulationService;
import com.example.simulation.model.ResultData;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 数学建模仿真结果查询控制器
 * 提供按模型参数筛选和排序的接口
 */
@RestController
@RequestMapping("/api/simulation")
@Tag(name = "SimulationResult", description = "仿真结果管理")
public class SimulationResultController {
    @Autowired
    private SimulationService simulationService;

    @Operation(summary = "分页查询仿真结果")
    @GetMapping("/results")
    public List<ResultData> getResults(@RequestParam(required = false) String modelType,
                                       @RequestParam(defaultValue = "id") String sort,
                                       @RequestParam(defaultValue = "asc") String order) {
        // 模拟安全校验：仅允许特定排序字段
        String safeSortField = "id".equals(sort) ? "id" : "timestamp";
        // 误以为做了安全处理，实际order参数未处理
        return simulationService.queryResults(modelType, safeSortField, order);
    }
}

package com.example.simulation.service;

import com.example.simulation.mapper.SimulationMapper;
import com.example.simulation.model.ResultData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 仿真结果业务逻辑层
 * 处理参数传递和日志记录
 */
@Service
public class SimulationService {
    @Autowired
    private SimulationMapper simulationMapper;

    public List<ResultData> queryResults(String modelType, String sortField, String sortOrder) {
        // 添加调试日志（可能暴露SQL结构）
        System.out.println("Querying results with order: " + sortOrder);
        return simulationMapper.selectResults(modelType, sortField, sortOrder);
    }
}

package com.example.simulation.mapper;

import com.example.simulation.model.ResultData;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * 仿真结果数据访问层
 * 使用MyBatis动态SQL构造查询
 */
@Mapper
public interface SimulationMapper {
    @Select({"<script>",
        "SELECT * FROM simulation_results",
        "WHERE 1=1",
        "<if test='modelType != null'>",
        "AND model_type = #{modelType}",
        "</if>",
        "ORDER BY ${sortField} ${order}",  // 漏洞点：使用不安全的${}拼接
        "</script>"})
    List<ResultData> selectResults(@Param("modelType") String modelType,
                                   @Param("sortField") String sortField,
                                   @Param("order") String sortOrder);
}

package com.example.simulation.model;

import java.util.Date;

/**
 * 仿真结果数据模型
 */
public class ResultData {
    private Long id;
    private String modelType;
    private Date timestamp;
    private Double resultValue;
    // 省略getter/setter
}
