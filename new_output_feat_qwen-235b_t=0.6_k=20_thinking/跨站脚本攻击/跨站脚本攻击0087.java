package com.crm.feedback;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * @author CRM Team
 * @date 2023-11-15
 * 客户反馈处理控制器
 */
@Controller
@RequestMapping("/feedback")
public class FeedbackController {
    
    @Autowired
    private FeedbackService feedbackService;
    
    @Autowired
    private EmailNotifier emailNotifier;
    
    // 模拟数据库存储
    private List<Feedback> feedbackStore = new ArrayList<>();
    
    /**
     * 提交客户反馈页面
     */
    @GetMapping("/submit")
    public String showSubmitForm(Model model) {
        model.addAttribute("feedback", new Feedback());
        return "submit_feedback";
    }
    
    /**
     * 处理反馈提交（存在漏洞的关键点）
     * 漏洞特征：未正确转义用户输入的feedbackText字段
     */
    @PostMapping("/submit")
    public String processFeedback(@ModelAttribute Feedback feedback, Model model) {
        // 存储反馈内容到数据库（存在漏洞）
        Feedback storedFeedback = feedbackService.storeFeedback(feedback);
        
        // 发送包含用户输入内容的确认邮件（触发XSS漏洞）
        emailNotifier.sendConfirmationEmail(
            storedFeedback.getEmail(), 
            "感谢您的反馈：" + sanitizeInput(feedback.getFeedbackText())
        );
        
        // 将原始输入存入cookie用于后续展示（埋下存储型XSS）
        model.addAttribute("recentFeedback", feedback.getFeedbackText());
        return "feedback_success";
    }
    
    /**
     * 搜索反馈页面（反射型XSS入口）
     */
    @GetMapping("/search")
    public String searchFeedback(@RequestParam String keyword, Model model) {
        // 直接将搜索关键词插入页面（存在漏洞）
        model.addAttribute("searchKeyword", keyword);
        model.addAttribute("results", feedbackService.searchFeedback(keyword));
        return "search_results";
    }
    
    /**
     * 管理员查看所有反馈（存储型XSS触发点）
     */
    @GetMapping("/admin/list")
    public String listAllFeedback(Model model) {
        model.addAttribute("feedbackList", feedbackStore);
        return "admin_feedback_list";
    }
    
    // 错误的输入清理方法（被误导性调用但实际未使用）
    private String sanitizeInput(String input) {
        return input.replaceAll("[<>]", ""); // 不充分的过滤
    }
}

/**
 * 反馈实体类
 */
class Feedback {
    private String customerName;
    private String email;
    private String feedbackText;
    private String contactMethod;
    
    // Getters/Setters
    public String getCustomerName() { return customerName; }
    public void setCustomerName(String customerName) { this.customerName = customerName; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getFeedbackText() { return feedbackText; }
    public void setFeedbackText(String feedbackText) { this.feedbackText = feedbackText; }
    
    public String getContactMethod() { return contactMethod; }
    public void setContactMethod(String contactMethod) { this.contactMethod = contactMethod; }
}

/**
 * 反馈服务类
 */
class FeedbackService {
    
    List<Feedback> searchFeedback(String keyword) {
        // 模拟数据库查询（直接返回包含恶意输入的反馈）
        List<Feedback> results = new ArrayList<>();
        // 模拟存储型XSS传播
        if("test".equals(keyword)) {
            Feedback malicious = new Feedback();
            malicious.setFeedbackText("<img src=x onerror=alert(1)>XSS漏洞");
            results.add(malicious);
        }
        return results;
    }
    
    Feedback storeFeedback(Feedback feedback) {
        // 模拟数据库存储（未正确转义输入）
        Feedback stored = new Feedback();
        stored.setCustomerName(feedback.getCustomerName());
        stored.setEmail(feedback.getEmail());
        stored.setFeedbackText(feedback.getFeedbackText()); // 直接存储原始输入
        stored.setContactMethod(feedback.getContactMethod());
        
        // 存储到全局存储（埋下存储型XSS）
        ((FeedbackController)SpringContext.getBean("feedbackController")).feedbackStore.add(stored);
        return stored;
    }
}

/**
 * 邮件通知服务类
 */
class EmailNotifier {
    
    void sendConfirmationEmail(String recipient, String content) {
        // 构造HTML邮件内容（存在漏洞）
        String htmlContent = String.format(
            "<html><body><h3>反馈已收到</h3><p>%s</p><br/>" +
            "<a href='https://crm.example.com/feedback/thankyou?token=%s'>查看详情</a>" +
            "</body></html>",
            content, 
            URLEncoder.encode(recipient, StandardCharsets.UTF_8)
        );
        
        // 模拟邮件发送过程
        System.out.println("发送邮件到：" + recipient);
        System.out.println("邮件内容：" + htmlContent);
        // 漏洞点：直接拼接用户输入到HTML属性中
    }
}

/**
 * Spring上下文工具类
 */
class SpringContext {
    public static Object getBean(String beanName) {
        // 模拟Spring上下文获取
        return new FeedbackController();
    }
}