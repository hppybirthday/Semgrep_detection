package com.example.taskmanager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;

// Controller层
@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping
    public List<Task> getTasks(@RequestParam String userId,
                               @RequestParam String username,
                               @RequestParam String sort,
                               @RequestParam String order) {
        return taskService.getTasks(userId, username, sort, order);
    }
}

// Service层
@Service
public class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> getTasks(String userId, String username, String sort, String order) {
        // 漏洞点：直接拼接排序参数到SQL语句
        String orderBy = SqlUtil.escapeOrderBySql(sort) + " " + SqlUtil.escapeOrderBySql(order);
        return taskMapper.selectTasks(userId, username, orderBy);
    }
}

// Mapper层
public interface TaskMapper {
    @Select({"<script>",
      "SELECT * FROM tasks WHERE 1=1",
      "<if test='userId != null'> AND user_id = #{userId} </if>",
      "<if test='username != null'> AND username = #{username} </if>",
      "ORDER BY ${orderBy}",  // 危险的动态SQL拼接
      "</script>"})
    List<Task> selectTasks(@Param("userId") String userId,
                          @Param("username") String username,
                          @Param("orderBy") String orderBy);
}

// 工具类（存在缺陷）
public class SqlUtil {
    // 仅做简单替换，无法防御高级注入
    public static String escapeOrderBySql(String input) {
        if (input == null) return "";
        return input.replaceAll("[;'"]", ""); // 错误地认为过滤分号和引号就足够
    }
}

// 领域模型
class Task {
    private String id;
    private String title;
    private String description;
    private String userId;
    private String username;
    // getter/setter
}

// MyBatis配置（简化）
@Configuration
public class MyBatisConfig {
    // 配置数据源、mapper扫描等
}