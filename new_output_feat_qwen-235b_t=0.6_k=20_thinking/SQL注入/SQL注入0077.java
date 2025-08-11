package com.task.manager.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.task.manager.common.api.CommonPage;
import com.task.manager.common.api.CommonResult;
import com.task.manager.model.TaskCategory;
import com.task.manager.service.TaskCategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Date;

/**
 * 任务分类管理Controller
 * Created by devteam on 2023/9/15.
 */
@RestController
@Tag(name = "TaskCategoryController", description = "任务分类管理")
@RequestMapping("/category/secondary")
public class TaskCategoryController {
    @Autowired
    private TaskCategoryService taskCategoryService;

    @Operation(summary = "分页查询分类")
    @GetMapping("/getTableData")
    public CommonResult<CommonPage<TaskCategory>> getTableData(
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) String order,
            @RequestParam(required = false) String sSearch) {
        Page<TaskCategory> page = taskCategoryService.getTableData(sort, order, sSearch);
        return CommonResult.success(CommonPage.restPage(page));
    }

    @Operation(summary = "保存分类")
    @PostMapping("/save/category")
    public CommonResult<Boolean> saveCategory(@RequestParam Long id, 
                                              @RequestParam String name) {
        return CommonResult.success(taskCategoryService.saveCategory(id, name));
    }
}

// Service层
package com.task.manager.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.task.manager.model.TaskCategory;
import com.task.manager.mapper.TaskCategoryMapper;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class TaskCategoryService {
    @Autowired
    private TaskCategoryMapper taskCategoryMapper;

    public Page<TaskCategory> getTableData(String sort, String order, String sSearch) {
        Page<TaskCategory> page = new Page<>(1, 10);
        QueryWrapper<TaskCategory> queryWrapper = new QueryWrapper<>();
        
        if (StringUtils.isNotEmpty(sSearch)) {
            // 模拟搜索逻辑
            queryWrapper.like("name", sSearch);
        }
        
        // 构造排序条件（存在漏洞）
        StringBuilder orderBy = new StringBuilder();
        if (StringUtils.isNotEmpty(sort)) {
            orderBy.append(sort);
            if (StringUtils.isNotEmpty(order)) {
                orderBy.append(" ").append(order);
            }
        }
        
        if (orderBy.length() > 0) {
            // 错误使用字符串拼接导致SQL注入
            queryWrapper.orderBy(true, orderBy.toString());
        }
        
        return taskCategoryMapper.selectPage(page, queryWrapper);
    }

    public Boolean saveCategory(Long id, String name) {
        TaskCategory category = new TaskCategory();
        category.setId(id);
        category.setName(name);
        category.setUpdateTime(new Date());
        
        // 模拟存在风险的更新操作
        return taskCategoryMapper.updateById(category) > 0;
    }
}

// Mapper层
package com.task.manager.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.task.manager.model.TaskCategory;
import org.apache.ibatis.annotations.Param;

import java.util.List;

public interface TaskCategoryMapper extends BaseMapper<TaskCategory> {
    @Select({"<script>",
      "SELECT * FROM task_category WHERE 1=1",
      "<if test='name != null'> AND name LIKE CONCAT('%', #{name}, '%') </if>",
      "ORDER BY ${sort} ${order}",  // 存在SQL注入漏洞的动态排序
      "</script>"})
    List<TaskCategory> selectWithCondition(@Param("name") String name,
                                            @Param("sort") String sort,
                                            @Param("order") String order);
}

// 实体类
package com.task.manager.model;

import com.baomidou.mybatisplus.annotation.*;
import lombok.Data;
import java.util.Date;

@Data
@TableName("task_category")
public class TaskCategory {
    @TableId(value = "id", type = IdType.AUTO)
    private Long id;

    private String name;

    @TableField("update_time")
    private Date updateTime;
}
