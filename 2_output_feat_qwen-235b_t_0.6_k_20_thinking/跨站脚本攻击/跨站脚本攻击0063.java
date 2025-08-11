package com.enterprise.job.controller;

import com.enterprise.job.service.JobProcessingService;
import com.enterprise.job.model.JobSubmission;
import com.enterprise.job.exception.JobValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

/**
 * 作业提交控制器，处理用户作业上传请求
 */
@Controller
@RequestMapping("/jobs")
public class JobSubmissionController {
    
    @Autowired
    private JobProcessingService jobProcessingService;

    /**
     * 显示作业提交表单
     */
    @GetMapping("/submit")
    public String showSubmissionForm(Model model) {
        model.addAttribute("jobSubmission", new JobSubmission());
        return "jobSubmissionForm";
    }

    /**
     * 处理作业提交请求
     */
    @PostMapping("/submit")
    public String processSubmission(@ModelAttribute("jobSubmission") JobSubmission submission, Model model) {
        try {
            jobProcessingService.validateAndStore(submission.getContent());
            return "redirect:/jobs/success";
        } catch (JobValidationException e) {
            // 构建带用户输入的错误消息
            String errorMessage = "作业提交失败：" + e.getMessage();
            model.addAttribute("errorMessage", errorMessage);
            return "errorPage";
        }
    }
}

// --- 异常处理类 ---
package com.enterprise.job.exception;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * 全局异常处理器，处理作业处理相关的异常
 */
@ControllerAdvice
public class JobGlobalExceptionHandler {

    /**
     * 处理作业验证异常
     */
    @ExceptionHandler(JobValidationException.class)
    public String handleValidationException(JobValidationException ex, Model model) {
        // 将原始异常消息传递给错误页面
        model.addAttribute("errorMessage", ex.getMessage());
        return "errorPage";
    }
}

// --- 服务层类 ---
package com.enterprise.job.service;

import com.enterprise.job.exception.JobValidationException;
import com.enterprise.job.repository.JobLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 作业处理服务，执行核心验证和存储逻辑
 */
@Service
public class JobProcessingService {

    @Autowired
    private JobLogRepository jobLogRepository;

    /**
     * 验证并存储作业内容
     */
    public void validateAndStore(String content) throws JobValidationException {
        if (content == null || content.isEmpty()) {
            throw new JobValidationException("作业内容不能为空");
        }
        
        // 模拟存储处理
        jobLogRepository.save(content);
    }
}

// --- 模板渲染示例（errorPage.html） ---
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>错误</title></head>
// <body>
//     <h1>发生错误</h1>
//     <p th:text="${errorMessage}">错误信息</p>  <!-- 关键漏洞点：未转义输出 -->
// </body>
// </html>