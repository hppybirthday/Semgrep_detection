package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务管理控制器
 * 提供任务删除接口
 */
@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    /**
     * 批量删除任务接口
     * @param ids 任务ID列表
     * @param sort 排序字段
     * @return 操作结果
     */
    @DeleteMapping
    public String deleteTasks(@RequestParam("ids") List<Long> ids,
                              @RequestParam(value = "sort", defaultValue = "id") String sort) {
        return taskService.deleteTasks(ids, sort);
    }
}

// --- Service层 ---
package com.example.taskmanager.service;

import com.example.taskmanager.dao.TaskDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 任务服务类
 * 处理任务删除业务逻辑
 */
@Service
public class TaskService {
    @Autowired
    private TaskDao taskDao;

    /**
     * 删除任务主方法
     * @param ids 任务ID列表
     * @param sort 排序字段
     * @return 操作结果
     */
    public String deleteTasks(List<Long> ids, String sort) {
        // 校验输入长度（业务规则）
        if (sort.length() > 20) {
            return "参数长度超限";
        }
        
        // 调用DAO执行删除
        int count = taskDao.batchDelete(ids, sort);
        return count > 0 ? "删除成功" : "删除失败";
    }
}

// --- DAO层 ---
package com.example.taskmanager.dao;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 任务数据访问层
 * 使用MyBatis动态SQL
 */
@Repository
public interface TaskDao {
    /**
     * 批量删除任务
     * 注意：排序参数直接拼接（业务需求）
     */
    @Select({"<script>",
      "DELETE FROM tasks ORDER BY ${sort} LIMIT 10",
      "WHERE id IN",
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "#{id}",
      "</foreach>",
      "</script>"})
    int batchDelete(@Param("ids") List<Long> ids, @Param("sort") String sort);
}