package com.example.crawler.domain;

import org.apache.ibatis.annotations.*;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.List;

// 实体类
public class CrawlerTask {
    private Long id;
    private String name;
    private String status;
    // 省略getter/setter
}

// Mapper接口
@Mapper
public interface CrawlerTaskMapper {
    @Select("${sql}")
    List<CrawlerTask> searchTasks(@Param("sql") String sql);
}

// 领域服务
@Service
public class CrawlerTaskService {
    @Resource
    private CrawlerTaskMapper crawlerTaskMapper;

    public List<CrawlerTask> searchTasks(String name, String status) {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM crawler_tasks WHERE name LIKE '%" + name + "%'";
        if (status != null && !status.isEmpty()) {
            sql += " AND status = '" + status + "'";
        }
        return crawlerTaskMapper.searchTasks(sql);
    }
}

// 控制器
@RestController
@RequestMapping("/tasks")
public class CrawlerTaskController {
    @Autowired
    private CrawlerTaskService crawlerTaskService;

    @GetMapping("/search")
    public List<CrawlerTask> searchTasks(
        @RequestParam String name,
        @RequestParam(required = false) String status) {
        return crawlerTaskService.searchTasks(name, status);
    }
}