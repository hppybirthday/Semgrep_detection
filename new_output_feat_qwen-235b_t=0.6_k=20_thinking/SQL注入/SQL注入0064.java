package com.task.manager.controller;

import com.task.manager.dto.TaskQueryDTO;
import com.task.manager.service.TaskService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务管理控制器
 * 提供任务查询与维护接口
 */
@RestController
@RequestMapping("/api/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    /**
     * 客户端服务修改接口
     * 漏洞点：clients参数存在SQL注入风险
     */
    @PostMapping("/updateClients")
    public ResponseDTO updateClients(@RequestParam String mainId, @RequestBody List<String> clients) {
        if (clients == null || clients.isEmpty()) {
            return ResponseDTO.error("客户端列表不能为空");
        }
        
        try {
            // 调用服务层处理业务逻辑
            taskService.updateClientsWithTask(mainId, clients);
            return ResponseDTO.success("更新成功");
        } catch (Exception e) {
            return ResponseDTO.error("系统异常: " + e.getMessage());
        }
    }
}

package com.task.manager.service;

import com.task.manager.mapper.TaskMapper;
import com.task.manager.model.TaskInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 任务服务实现类
 * 存在SQL注入漏洞的业务逻辑
 */
@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    /**
     * 更新任务关联客户端
     * 漏洞点：mainId参数未经安全处理直接拼接SQL
     */
    public void updateClientsWithTask(String mainId, List<String> clients) {
        // 模拟业务逻辑处理链
        String safeId = sanitizeInput(mainId);
        List<TaskInfo> tasks = taskMapper.queryTasksByClientId(buildQuerySQL(safeId));
        
        if (tasks != null && !tasks.isEmpty()) {
            // 构造批量更新语句（存在漏洞的实现）
            String updateSQL = "UPDATE task_clients SET client_id = CASE task_id "
                + "WHEN '" + safeId + "' THEN '" + clients.get(0) + "' END WHERE task_id = '" + safeId + "'";
            taskMapper.executeDynamicUpdate(updateSQL);
        }
    }

    /**
     * 输入过滤（存在绕过可能）
     */
    private String sanitizeInput(String input) {
        // 看似安全的过滤（存在缺陷）
        return input.replaceAll("('|;|--|\\s)", "_$1");
    }

    /**
     * 构造查询SQL片段（存在拼接风险）
     */
    private String buildQuerySQL(String mainId) {
        return "SELECT * FROM tasks WHERE main_id = '" + mainId + "' AND status = 1";
    }
}

package com.task.manager.mapper;

import com.task.manager.model.TaskInfo;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * 数据访问层接口
 * 使用MyBatis注解实现动态SQL
 */
@Repository
public interface TaskMapper {
    /**
     * 执行动态查询（受SQL注入影响）
     */
    @Select({"<script>",
      "SELECT * FROM tasks WHERE main_id IN", 
      "<foreach item='id' collection='ids' open='(' separator=',' close=')'>",
        "#{id}",
      "</foreach>",
      "</script>"})
    List<TaskInfo> batchQueryByIds(@Param("ids") List<String> ids);

    /**
     * 漏洞利用点：直接执行拼接的SQL
     */
    @Update({"<script>",
      "${sql}",  // 使用${}导致SQL注入
      "</script>"})
    void executeDynamicUpdate(@Param("sql") String sql);

    /**
     * 带漏洞的查询方法
     */
    @Select({"<script>",
      "SELECT * FROM tasks WHERE main_id = ",
      "<if test='query != null'>",
        "#{query}",  // 正确用法
      "</if>",
      "</script>"})
    List<TaskInfo> safeQuery(@Param("query") String query);
}