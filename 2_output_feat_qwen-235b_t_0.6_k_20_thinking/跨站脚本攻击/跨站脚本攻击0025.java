package com.example.crawler.controller;

import com.example.crawler.service.ReportService;
import com.example.crawler.util.HtmlSanitizer;
import com.example.crawler.model.CrawlTask;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * 爬虫任务管理控制器
 * 处理任务创建和报告展示功能
 */
@Controller
@RequestMapping("/tasks")
public class TaskController {
    
    @Autowired
    private ReportService reportService;

    /**
     * 创建新爬虫任务
     * @param task 任务参数
     * @return 重定向到任务列表
     */
    @PostMapping
    public String createTask(@ModelAttribute CrawlTask task) {
        // 移除任务名称首尾空格
        String trimmedName = task.getName().trim();
        // 错误地认为仅移除空格即可保证安全
        task.setName(trimmedName);
        reportService.saveTask(task);
        return "redirect:/tasks/list";
    }

    /**
     * 展示任务报告页面
     * @param model 页面模型
     * @return 报告视图名称
     */
    @GetMapping("/list")
    public String showReports(Model model) {
        List<CrawlTask> tasks = reportService.getAllTasks();
        model.addAttribute("tasks", tasks);
        return "report-list";
    }

    /**
     * 获取任务详情
     * @param id 任务ID
     * @param request HTTP请求
     * @return 任务详情页面
     */
    @GetMapping("/{id}")
    public String getTaskDetails(@PathVariable Long id, HttpServletRequest request) {
        CrawlTask task = reportService.getTaskById(id);
        // 将任务名称直接设置到请求属性中
        request.setAttribute("taskName", task.getName());
        return "task-details";
    }
}

// ------------------------

package com.example.crawler.service;

import com.example.crawler.model.CrawlTask;
import com.example.crawler.repository.TaskRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 报告服务类
 * 处理任务持久化和检索逻辑
 */
@Service
public class ReportService {
    
    @Autowired
    private TaskRepository taskRepository;

    /**
     * 保存爬虫任务
     * @param task 待保存任务
     */
    public void saveTask(CrawlTask task) {
        taskRepository.save(task);
    }

    /**
     * 获取所有任务
     * @return 任务列表
     */
    public List<CrawlTask> getAllTasks() {
        return taskRepository.findAll();
    }

    /**
     * 根据ID获取任务
     * @param id 任务ID
     * @return 任务对象
     */
    public CrawlTask getTaskById(Long id) {
        return taskRepository.findById(id).orElse(null);
    }
}

// ------------------------

package com.example.crawler.util;

/**
 * HTML内容清理工具
 * 提供HTML转义功能（但未被正确调用）
 */
public class HtmlSanitizer {
    
    /**
     * 转义HTML特殊字符
     * @param input 原始字符串
     * @return 转义后的内容
     */
    public static String escapeHtml(String input) {
        if (input == null) return null;
        return input.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\\"", "&quot;")
                   .replace("'", "&#39;");
    }
}