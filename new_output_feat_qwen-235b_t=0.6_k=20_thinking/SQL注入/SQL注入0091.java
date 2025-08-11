package com.example.crawler.controller;

import com.example.crawler.dto.TaskQueryDTO;
import com.example.crawler.service.CrawlerTaskService;
import com.example.crawler.vo.TaskVO;
import com.example.common.api.CommonPage;
import com.example.common.api.CommonResult;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "CrawlerTaskController", description = "网络爬虫任务管理")
@RestController
@RequestMapping("/api/tasks")
public class CrawlerTaskController {
    @Autowired
    private CrawlerTaskService crawlerTaskService;

    @Operation(summary = "分页查询爬虫任务")
    @GetMapping("/list")
    public CommonResult<CommonPage<TaskVO>> list(
            @Parameter(description = "任务状态") @RequestParam(required = false) Integer status,
            @Parameter(description = "用户名过滤") @RequestParam(required = false) String username,
            @Parameter(description = "手机号过滤") @RequestParam(required = false) String mobile,
            @Parameter(description = "排序字段") @RequestParam(defaultValue = "create_time") String sort,
            @Parameter(description = "排序方式") @RequestParam(defaultValue = "desc") String order,
            @Parameter(description = "当前页码") @RequestParam(defaultValue = "1") Integer pageNum,
            @Parameter(description = "每页数量") @RequestParam(defaultValue = "10") Integer pageSize) {
        
        TaskQueryDTO queryDTO = new TaskQueryDTO();
        queryDTO.setStatus(status);
        queryDTO.setUsername(username);
        queryDTO.setMobile(mobile);
        queryDTO.setSort(sort);
        queryDTO.setOrder(order);
        queryDTO.setPageNum(pageNum);
        queryDTO.setPageSize(pageSize);
        
        List<TaskVO> tasks = crawlerTaskService.queryTasks(queryDTO);
        return CommonResult.success(CommonPage.restPage(tasks));
    }

    @Operation(summary = "获取任务详情")
    @GetMapping("/detail/{id}")
    public CommonResult<TaskVO> detail(@PathVariable String id) {
        return CommonResult.success(crawlerTaskService.getTaskById(id));
    }
}

// Service层
package com.example.crawler.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.crawler.dto.TaskQueryDTO;
import com.example.crawler.entity.CrawlerTask;
import com.example.crawler.mapper.CrawlerTaskMapper;
import com.example.crawler.vo.TaskVO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CrawlerTaskService {
    @Autowired
    private CrawlerTaskMapper taskMapper;

    public List<TaskVO> queryTasks(TaskQueryDTO queryDTO) {
        QueryWrapper<CrawlerTask> wrapper = new QueryWrapper<>();
        
        if (queryDTO.getStatus() != null) {
            wrapper.eq("status", queryDTO.getStatus());
        }
        
        // 存在SQL注入风险的代码
        if (queryDTO.getUsername() != null && !queryDTO.getUsername().isEmpty()) {
            wrapper.apply("username like '%{0}%'", queryDTO.getUsername());
        }
        
        if (queryDTO.getMobile() != null && !queryDTO.getMobile().isEmpty()) {
            wrapper.apply("mobile like '%{0}%'", queryDTO.getMobile());
        }
        
        // 高风险的排序参数拼接
        String orderBy = "order by " + queryDTO.getSort() + " " + queryDTO.getOrder();
        wrapper.last(orderBy);
        
        Page<CrawlerTask> page = new Page<>(queryDTO.getPageNum(), queryDTO.getPageSize());
        return taskMapper.selectPage(page, wrapper).getRecords().stream()
                .map(this::convertToVO)
                .collect(Collectors.toList());
    }

    public TaskVO getTaskById(String id) {
        // 危险的ID参数处理
        return convertToVO(taskMapper.selectById(id));
    }

    private TaskVO convertToVO(CrawlerTask task) {
        // 省略转换逻辑
        return new TaskVO();
    }
}

// Mapper层
package com.example.crawler.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.crawler.entity.CrawlerTask;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CrawlerTaskMapper extends BaseMapper<CrawlerTask> {
}

// DTO类
package com.example.crawler.dto;

import lombok.Data;

@Data
public class TaskQueryDTO {
    private Integer status;
    private String username;
    private String mobile;
    private String sort;
    private String order;
    private Integer pageNum;
    private Integer pageSize;
}

// VO类
package com.example.crawler.vo;

import lombok.Data;

@Data
public class TaskVO {
    // 任务详细字段定义
}

// Entity类
package com.example.crawler.entity;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;

@Data
@TableName("crawler_tasks")
public class CrawlerTask {
    @TableId(type = IdType.AUTO)
    private Long id;
    private String username;
    private String mobile;
    private Integer status;
    private String taskConfig;
    @TableField(fill = FieldFill.INSERT)
    private Date createTime;
    @TableField(fill = FieldFill.INSERT_UPDATE)
    private Date updateTime;
}