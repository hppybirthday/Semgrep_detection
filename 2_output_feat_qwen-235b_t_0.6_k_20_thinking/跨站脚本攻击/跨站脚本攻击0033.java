package com.crm.customer.controller;

import com.crm.customer.service.CustomerFeedbackService;
import com.crm.customer.dto.FeedbackDTO;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.RequiredArgsConstructor;
import org.springframework.web.servlet.ModelAndView;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 客户反馈处理控制器
 * 处理客户提交的反馈信息并展示
 */
@Controller
@RequiredArgsConstructor
@RequestMapping("/feedback")
public class CustomerFeedbackController {
    private final CustomerFeedbackService feedbackService;

    /**
     * 显示反馈提交表单
     */
    @GetMapping("/submit")
    public String showSubmissionForm(Model model) {
        model.addAttribute("feedback", new FeedbackDTO());
        return "feedback-form";
    }

    /**
     * 处理反馈提交请求
     */
    @PostMapping("/submit")
    public String processSubmission(@ModelAttribute FeedbackDTO feedback, Model model) {
        // 验证输入长度（业务规则）
        if (feedback.getContent().length() > 500) {
            model.addAttribute("error", "反馈内容超出最大长度限制");
            return "feedback-form";
        }

        // 保存反馈信息到数据库
        feedbackService.saveFeedback(feedback);
        return "redirect:/feedback/list";
    }

    /**
     * 展示所有反馈列表
     */
    @GetMapping("/list")
    public ModelAndView listAllFeedbacks() {
        List<FeedbackDTO> feedbacks = feedbackService.getAllFeedbacks().stream()
            .map(this::sanitizeFeedback)
            .collect(Collectors.toList());

        return new ModelAndView("feedback-list", "feedbacks", feedbacks);
    }

    /**
     * 对反馈内容进行基础过滤
     * 移除特殊字符（业务规则）
     */
    private FeedbackDTO sanitizeFeedback(FeedbackDTO feedback) {
        FeedbackDTO result = new FeedbackDTO();
        result.setId(feedback.getId());
        result.setContent(feedback.getContent()
            .replace("<script>", "")
            .replace("</script>", ""));
        return result;
    }
}