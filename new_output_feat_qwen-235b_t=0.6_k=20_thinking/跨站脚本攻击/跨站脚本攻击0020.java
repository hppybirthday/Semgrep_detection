package com.smartiot.controller;

import com.smartiot.service.DeviceCategoryService;
import com.smartiot.service.EmailService;
import com.smartiot.entity.DeviceCategoryEntity;
import com.smartiot.repository.DeviceCategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * 设备分类管理控制器
 * @author IoT Security Team
 */
@Controller
@RequestMapping("/device/category")
public class DeviceCategoryController {
    
    @Autowired
    private DeviceCategoryService deviceCategoryService;

    @Autowired
    private EmailService emailService;

    /**
     * 创建新设备分类
     * @param categoryName 分类名称
     * @param parentId 父分类ID
     * @param backParentId 备份父分类ID
     * @param categoryLevel 分类层级
     * @param request HTTP请求
     * @return 操作结果
     */
    @PostMapping("/create")
    @ResponseBody
    public Map<String, Object> createCategory(@RequestParam String categoryName,
                                              @RequestParam(required = false) String parentId,
                                              @RequestParam(required = false) String backParentId,
                                              @RequestParam int categoryLevel,
                                              HttpServletRequest request) {
        Map<String, Object> result = new HashMap<>();
        try {
            // 验证层级有效性
            if (categoryLevel < 1 || categoryLevel > 5) {
                throw new IllegalArgumentException("Invalid category level");
            }

            // 调用服务层创建分类
            DeviceCategoryEntity category = deviceCategoryService.createCategory(
                categoryName, parentId, backParentId, categoryLevel
            );

            // 发送通知邮件（漏洞触发点隐藏在此处）
            emailService.notifyAdminNewCategory(category);

            result.put("status", "success");
            result.put("categoryId", category.getId());
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
        }
        return result;
    }

    // 其他安全方法（用于混淆）
    @GetMapping("/safe")
    @ResponseBody
    public String safeMethod(@RequestParam String input) {
        return sanitizeInput(input);
    }

    private String sanitizeInput(String input) {
        return input.replaceAll("[<>&'\\"/\\\\]", ""); // 简单过滤（实际未被调用）
    }
}

// -----------------------------

package com.smartiot.service;

import com.smartiot.entity.DeviceCategoryEntity;
import com.smartiot.repository.DeviceCategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class DeviceCategoryService {

    @Autowired
    private DeviceCategoryRepository categoryRepository;

    @Autowired
    private EmailService emailService;

    public DeviceCategoryEntity createCategory(String categoryName, String parentId,
                                              String backParentId, int categoryLevel) {
        DeviceCategoryEntity entity = new DeviceCategoryEntity();
        entity.setCategoryName(categoryName);
        entity.setParentId(parentId);
        entity.setBackParentId(backParentId);
        entity.setCategoryLevel(categoryLevel);
        entity.setCreateTime(new Date());
        
        // 存储用户输入到数据库（未进行XSS清理）
        DeviceCategoryEntity saved = categoryRepository.save(entity);
        
        // 触发邮件通知（间接传递未过滤数据）
        emailService.sendCategoryNotification(saved);
        
        return saved;
    }
}

// -----------------------------

package com.smartiot.service;

import com.smartiot.entity.DeviceCategoryEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import javax.mail.internet.MimeMessage;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void notifyAdminNewCategory(DeviceCategoryEntity category) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            
            helper.setTo("admin@smartiot.com");
            helper.setSubject("新设备分类创建通知");
            
            // 构造HTML邮件内容（直接使用用户输入）
            String content = buildEmailContent(category);
            
            // 危险操作：将未经转义的用户输入作为HTML内容
            helper.setText(content, true);
            
            mailSender.send(message);
        } catch (Exception e) {
            // 日志记录异常（隐藏安全问题）
            System.err.println("Failed to send email notification: " + e.getMessage());
        }
    }

    private String buildEmailContent(DeviceCategoryEntity category) {
        StringBuilder content = new StringBuilder();
        content.append("<div style='font-family: Arial'>");
        content.append("<h2>新设备分类已创建</h2>");
        content.append("<p>分类名称: <strong>").append(category.getCategoryName()).append("</strong></p>");
        content.append("<p>层级: ").append(category.getCategoryLevel()).append("</p>");
        content.append("</div>");
        return content.toString();
    }

    // 其他邮件发送方法（用于混淆）
    public void sendCategoryNotification(DeviceCategoryEntity category) {
        // 实际调用主要通知方法
        notifyAdminNewCategory(category);
    }
}