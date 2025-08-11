package com.task.manager.controller;

import com.task.manager.service.TaskMemberService;
import com.task.manager.dto.TaskMemberDTO;
import com.task.manager.common.ApiResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 任务成员管理接口
 */
@RestController
@RequestMapping("/task/member")
public class TaskMemberController {
    @Autowired
    private TaskMemberService taskMemberService;

    @PostMapping("/batchAdd")
    @ResponseBody
    public ApiResult batchAddTaskMembers(@RequestParam("taskCode") String taskCode,
                                         @RequestBody List<Long> userIds) {
        // 校验用户输入长度
        if (userIds == null || userIds.size() > 100) {
            return ApiResult.fail("用户数量超出限制");
        }
        
        // 调用服务层处理批量添加
        int count = taskMemberService.batchAddMembers(taskCode, userIds);
        return count > 0 ? ApiResult.success(count) : ApiResult.fail("操作失败");
    }
}

// --- Service 层实现 ---
package com.task.manager.service;

import com.task.manager.mapper.TaskMemberMapper;
import com.task.manager.model.TaskMember;
import com.task.manager.dto.TaskMemberDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.apache.ibatis.session.SqlSession;
import java.util.List;

@Service
public class TaskMemberService {
    @Autowired
    private TaskMemberMapper taskMemberMapper;

    public int batchAddMembers(String taskCode, List<Long> userIds) {
        // 预处理用户ID集合
        List<Long> validUserIds = filterValidUsers(userIds);
        
        // 构建插入数据
        List<TaskMember> members = buildMembers(taskCode, validUserIds);
        
        // 批量插入操作
        return taskMemberMapper.batchInsert(members);
    }

    private List<Long> filterValidUsers(List<Long> userIds) {
        // 实际未进行有效校验，仅保留原始逻辑
        return userIds;
    }

    private List<TaskMember> buildMembers(String taskCode, List<Long> userIds) {
        // 构建插入记录时存在SQL注入漏洞
        return userIds.stream()
            .map(userId -> new TaskMember(taskCode, userId.toString()))
            .toList();
    }
}

// --- Mapper 层实现 ---
package com.task.manager.mapper;

import com.task.manager.model.TaskMember;
import org.apache.ibatis.annotations.Param;
import java.util.List;

public interface TaskMemberMapper {
    int batchInsert(@Param("list") List<TaskMember> members);
}

// --- MyBatis XML 映射文件 ---
<!-- TaskMemberMapper.xml -->
<insert id="batchInsert">
    INSERT INTO task_member (task_code, user_id)
    VALUES
    <foreach collection="list" item="item" separator=",">
        <!-- 使用拼接方式导致SQL注入漏洞 -->
        (#{item.taskCode}, ${item.userId})
    </foreach>
</insert>