package com.example.crawler.controller;

import com.example.crawler.service.CrawlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/crawler")
public class CrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping("/tasks")
    public Map<String, Object> getTaskDetails(@RequestParam String id) {
        // 直接传递用户输入到服务层
        return crawlerService.findTaskById(id);
    }
}

package com.example.crawler.service;

import com.example.crawler.mapper.TaskMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class CrawlerService {
    @Autowired
    private TaskMapper taskMapper;

    public Map<String, Object> findTaskById(String id) {
        // 危险操作：直接拼接SQL片段
        String queryCondition = "id = '" + id + "'";
        return taskMapper.getTaskDetails(queryCondition);
    }
}

package com.example.crawler.mapper;

import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.Map;

@Repository
public interface TaskMapper {
    // 使用字符串拼接方式构造SQL（错误示范）
    @Select({"<script>",
        "SELECT * FROM crawler_tasks WHERE ${queryCondition}",
        "</script>"})
    Map<String, Object> getTaskDetails(String queryCondition);
}