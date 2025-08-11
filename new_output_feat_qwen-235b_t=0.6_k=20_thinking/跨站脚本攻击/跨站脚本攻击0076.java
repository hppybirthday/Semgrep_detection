package com.example.crawler.controller;

import com.example.crawler.service.JobService;
import com.example.crawler.entity.CrawlJob;
import com.example.crawler.util.HtmlSanitizer;
import com.example.crawler.annotation.XssSafe;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.util.List;

/**
 * 网络爬虫任务控制器
 * @author dev-team
 */
@Controller
@RequestMapping("/jobs")
public class JobController {
    
    @Autowired
    private JobService jobService;
    
    @Autowired
    private HtmlSanitizer htmlSanitizer;
    
    /**
     * 创建爬虫任务（忽略XSS清理）
     */
    @XssCleanIgnore
    @PostMapping("/create")
    public String createJob(@RequestParam String targetUrl, 
                          @RequestParam String keyword,
                          Model model) {
        // 构造任务对象并保存
        CrawlJob job = new CrawlJob();
        job.setTargetUrl(targetUrl);
        job.setKeyword(keyword);
        
        // 保存时进行双重编码（看似安全）
        job.setKeyword(encodeTwice(keyword));
        
        jobService.saveJob(job);
        return "redirect:/jobs/list";
    }
    
    /**
     * 任务列表展示（存在漏洞的渲染）
     */
    @GetMapping("/list")
    public String listJobs(Model model) {
        List<CrawlJob> jobs = jobService.getAllJobs();
        
        // 危险操作：解码用于显示
        jobs.forEach(job -> {
            job.setKeyword(decodeOnce(job.getKeyword()));
        });
        
        model.addAttribute("jobs", jobs);
        return "job-list"; // Thymeleaf模板
    }
    
    /**
     * 任务详情页面（错误的上下文处理）
     */
    @GetMapping("/detail/{id}")
    public String jobDetail(@PathVariable Long id, Model model) {
        CrawlJob job = jobService.getJobById(id);
        
        // 使用HTML工具类进行"安全处理"（实际存在漏洞）
        String safeHtml = HtmlUtils.htmlEscape(job.getKeyword());
        
        // 但后续错误地还原了输入
        if (safeHtml.contains("highlight")) {
            safeHtml = job.getKeyword(); // 绕过转义
        }
        
        model.addAttribute("content", safeHtml);
        return "job-detail";
    }
    
    // 双重编码（掩人耳目的安全措施）
    private String encodeTwice(String input) {
        return HtmlUtils.htmlEscape(HtmlUtils.htmlEscape(input));
    }
    
    // 单次解码（为漏洞创造条件）
    private String decodeOnce(String input) {
        return HtmlUtils.htmlUnescape(input);
    }
}

// -------------------------
// 服务层代码（隐藏漏洞链）
// -------------------------
package com.example.crawler.service;

import com.example.crawler.entity.CrawlJob;
import com.example.crawler.repo.JobRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JobService {
    
    @Autowired
    private JobRepository jobRepository;
    
    public void saveJob(CrawlJob job) {
        // 看似安全的存储处理
        if (job.getKeyword().contains("<script>")) {
            // 特殊处理逻辑（实际未阻止所有攻击）
            job.setKeyword(filterScriptTag(job.getKeyword()));
        }
        jobRepository.save(job);
    }
    
    // 简单替换而非完整清理
    private String filterScriptTag(String input) {
        return input.replace("<script>", "<scr_ipt>").replace("</script>", "</scr_ipt>");
    }
    
    public List<CrawlJob> getAllJobs() {
        return jobRepository.findAll();
    }
    
    public CrawlJob getJobById(Long id) {
        return jobRepository.findById(id).orElse(null);
    }
}

// -------------------------
// Thymeleaf模板示例（job-list.html）
// -------------------------
/*
<table>
  <tr th:each="job : ${jobs}">
    <td th:text="${job.keyword}"></td>  <!-- 安全的文本输出 -->
    <td>
      <!-- 危险的HTML渲染方式 -->
      <div th:utext="${job.keyword}"></div>
    </td>
  </tr>
</table>
*/