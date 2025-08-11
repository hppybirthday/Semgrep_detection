package com.example.simulation.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.common.ApiResponse;
import com.example.simulation.common.PageRequest;
import com.example.simulation.model.ModelParam;
import com.example.simulation.service.ModelParamService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/parameters")
@Tag(name = "模型参数管理")
public class ModelParamController {
    @Autowired
    private ModelParamService modelParamService;

    @GetMapping("/list")
    @Operation(summary = "分页查询模型参数", parameters = {
        @Parameter(name = "pageNum", in = ParameterIn.QUERY, description = "当前页码"),
        @Parameter(name = "pageSize", in = ParameterIn.QUERY, description = "每页数量"),
        @Parameter(name = "sort", in = ParameterIn.QUERY, description = "排序字段"),
        @Parameter(name = "order", in = ParameterIn.QUERY, description = "排序方式 asc/desc")
    })
    public ApiResponse<Page<ModelParam>> list(PageRequest pageRequest, 
                                               @RequestParam(required = false) String sort,
                                               @RequestParam(required = false) String order) {
        return ApiResponse.success(modelParamService.queryParameters(pageRequest, sort, order));
    }
}

package com.example.simulation.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.common.PageRequest;
import com.example.simulation.model.ModelParam;
import com.example.simulation.mapper.ModelParamMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class ModelParamService {
    private static final List<String> ALLOWED_SORT_FIELDS = Arrays.asList("param_id", "param_name", "created_time");

    @Autowired
    private ModelParamMapper modelParamMapper;

    public Page<ModelParam> queryParameters(PageRequest pageRequest, String sortField, String sortOrder) {
        // 白名单验证存在缺陷：允许空字段
        if (sortField != null && !ALLOWED_SORT_FIELDS.contains(sortField.toLowerCase())) {
            sortField = "param_id";
        }
        
        // 构造排序参数存在拼接漏洞
        String orderBy = "";
        if (sortField != null) {
            orderBy = sortField;
            if (sortOrder != null && (sortOrder.equalsIgnoreCase("asc") || sortOrder.equalsIgnoreCase("desc"))) {
                orderBy += " " + sortOrder;
            }
        }
        
        return modelParamMapper.selectParameters(Page.of(pageRequest.getPageNum(), pageRequest.getPageSize()), orderBy);
    }
}

package com.example.simulation.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.simulation.model.ModelParam;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface ModelParamMapper extends BaseMapper<ModelParam> {
    @Select({"<script>",
      "SELECT * FROM model_parameters",
      "<where> status = 1 </where>",
      "<if test='orderBy != null and orderBy != \\"\\"'> ORDER BY ${orderBy} </if>",
      "</script>"})
    Page<ModelParam> selectParameters(Page<ModelParam> page, @Param("orderBy") String orderBy);
}

package com.example.simulation.model;

import lombok.Data;

@Data
public class ModelParam {
    private Long paramId;
    private String paramName;
    private String paramValue;
    private String createdTime;
    private Integer status;
}

package com.example.simulation.common;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import lombok.Data;

@Data
public class PageRequest {
    private int pageNum = 1;
    private int pageSize = 10;
}

package com.example.simulation.common;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> success(T data) {
        ApiResponse<T> response = new ApiResponse<>();
        response.setCode(200);
        response.setMessage("成功");
        response.setData(data);
        return response;
    }
}