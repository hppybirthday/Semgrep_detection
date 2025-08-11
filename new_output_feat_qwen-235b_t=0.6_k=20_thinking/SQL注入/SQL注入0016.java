package com.example.crawler.controller;

import com.baomidou.mybatisplus.core.conditions.query.Query;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.crawler.dto.TaskQueryDTO;
import com.example.crawler.entity.CrawlTask;
import com.example.crawler.service.CrawlTaskService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 网络爬虫任务管理Controller
 * 模拟支持动态排序的分页查询接口
 */
@RestController
@RequestMapping("/api/tasks")
@Api(tags = "爬虫任务管理")
public class CrawlTaskController {
    @Autowired
    private CrawlTaskService crawlTaskService;

    @GetMapping("/list")
    @ApiOperation("分页查询爬虫任务")
    @ApiImplicitParams({
        @ApiImplicitParam(name = "pageNum", value = "当前页码", required = true, dataType = "int"),
        @ApiImplicitParam(name = "pageSize", value = "每页数量", required = true, dataType = "int"),
        @ApiImplicitParam(name = "sortBy", value = "排序字段", dataType = "string"),
        @ApiImplicitParam(name = "sortOrder", value = "排序方式(asc/desc)", dataType = "string")
    })
    public Page<CrawlTask> listTasks(@RequestParam int pageNum,
                                     @RequestParam int pageSize,
                                     @RequestParam(required = false) String sortBy,
                                     @RequestParam(required = false) String sortOrder) {
        return crawlTaskService.getTasks(pageNum, pageSize, sortBy, sortOrder);
    }
}

package com.example.crawler.service;

import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.core.conditions.query.Query;
import com.example.crawler.entity.CrawlTask;
import com.example.crawler.mapper.CrawlTaskMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CrawlTaskService {
    @Autowired
    private CrawlTaskMapper crawlTaskMapper;

    public Page<CrawlTask> getTasks(int pageNum, int pageSize, String sortBy, String sortOrder) {
        // 构建查询条件
        Query<CrawlTask> query = new Query<>();
        
        // 动态排序处理（存在SQL注入漏洞的关键点）
        if (sortBy != null && sortOrder != null) {
            String safeSortField = sanitizeSortField(sortBy);
            String safeSortOrder = sanitizeSortOrder(sortOrder);
            query.apply("ORDER BY {0} {1}", safeSortField, safeSortOrder);
        }
        
        return crawlTaskMapper.selectPage(new Page<>(pageNum, pageSize), query);
    }

    // 模拟不充分的字段过滤（存在绕过可能）
    private String sanitizeSortField(String field) {
        // 仅允许特定字段排序（存在白名单绕过漏洞）
        if (field.matches("(task_id|url|status|priority|create_time|update_time)")) {
            return field;
        }
        return "task_id";
    }

    // 不安全的排序方式处理
    private String sanitizeSortOrder(String order) {
        // 错误地允许直接拼接排序方式（存在注入点）
        if (order.equalsIgnoreCase("desc")) {
            return "desc";
        }
        return "asc";
    }
}

package com.example.crawler.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.crawler.entity.CrawlTask;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface CrawlTaskMapper extends BaseMapper<CrawlTask> {
}

package com.example.crawler.entity;

import lombok.Data;

/**
 * 网络爬虫任务实体
 */
@Data
public class CrawlTask {
    private Long taskId;
    private String url;
    private Integer status;
    private Integer priority;
    private Long createTime;
    private Long updateTime;
}

package com.example.crawler.dto;

import lombok.Data;

@Data
public class TaskQueryDTO {
    private int pageNum;
    private int pageSize;
    private String sortBy;
    private String sortOrder;
}