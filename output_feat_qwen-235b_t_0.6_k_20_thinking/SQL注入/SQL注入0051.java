import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.commons.lang3.StringUtils;
import java.util.List;

// SQL注入漏洞示例：任务管理系统中的排序功能
@RestController
@RequestMapping("/tasks")
public class TaskController {
    @Autowired
    private TaskService taskService;

    @GetMapping
    public List<Task> getTasks(@RequestParam String orderField) {
        return taskService.getTasks(orderField);
    }
}

@Service
class TaskService {
    @Autowired
    private TaskMapper taskMapper;

    public List<Task> getTasks(String orderField) {
        String safeOrderField = SqlUtil.escapeOrderBySql(orderField);
        QueryWrapper<Task> queryWrapper = new QueryWrapper<>();
        // 漏洞点：直接使用未经严格验证的排序字段参数
        queryWrapper.orderBy(StringUtils.isNotBlank(safeOrderField), safeOrderField);
        return taskMapper.selectList(queryWrapper);
    }
}

// 存在缺陷的SQL转义工具类
class SqlUtil {
    // 错误实现：仅过滤分号无法阻止所有注入攻击
    static String escapeOrderBySql(String input) {
        return (input == null) ? null : input.replaceAll(";", "");
    }
}

// 数据实体
class Task {
    private Long id;
    private String taskName;
    private String status;
    // 实际场景中包含getter/setter
}

interface TaskMapper extends BaseMapper<Task> {
    // MyBatis Plus底层使用动态SQL拼接orderField
}
// 攻击示例：orderField参数传入 "task_name, (SELECT USER())" 将生成
// ORDER BY task_name, (SELECT USER()) 导致敏感信息泄露