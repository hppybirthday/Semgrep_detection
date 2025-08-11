package com.taskmanager.controller;

import com.taskmanager.service.TaskService;
import com.taskmanager.model.Task;
import com.taskmanager.util.JsonResponse;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

public class TaskController {
    private TaskService taskService;

    public JsonResponse updateTaskStatus(HttpServletRequest request) {
        try {
            String[] ids = request.getParameterValues("ids");
            String status = request.getParameter("status");
            
            // 漏洞点：未校验ids参数直接传递
            List<String> idList = Arrays.asList(ids);
            taskService.updateStatus(idList, status);
            return JsonResponse.success("状态更新成功");
        } catch (Exception e) {
            return JsonResponse.error("操作失败: " + e.getMessage());
        }
    }
}

package com.taskmanager.service;

import java.util.List;

public interface TaskService {
    void updateStatus(List<String> ids, String status);
}

package com.taskmanager.service.impl;

import com.taskmanager.service.TaskService;
import com.taskmanager.mapper.TaskMapper;
import java.util.List;

public class TaskServiceImpl implements TaskService {
    private TaskMapper taskMapper;

    @Override
    public void updateStatus(List<String> ids, String status) {
        // 漏洞点：直接拼接参数
        String idStr = String.join(",", ids);
        taskMapper.updateTaskStatus(idStr, status);
    }
}

package com.taskmanager.mapper;

import org.apache.ibatis.annotations.Param;

public interface TaskMapper {
    // 漏洞点：使用${}进行SQL拼接
    void updateTaskStatus(@Param("ids") String ids, @Param("status") String status);
}

// MyBatis XML配置
// <update id="updateTaskStatus">
//     UPDATE tasks SET status = #{status}
//     WHERE id IN (${ids})
// </update>