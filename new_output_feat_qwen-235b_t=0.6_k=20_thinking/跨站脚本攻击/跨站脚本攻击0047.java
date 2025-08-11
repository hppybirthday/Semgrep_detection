package com.taskmanager.payment.controller;

import com.taskmanager.payment.service.PaymentService;
import com.taskmanager.payment.model.PaymentRequest;
import com.taskmanager.payment.model.PaymentResponse;
import com.taskmanager.payment.util.PaymentValidator;
import com.taskmanager.payment.filter.XssFilter;
import com.taskmanager.payment.encoder.HtmlEncoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.thymeleaf.spring6.context.webflux.SpringWebFluxContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Controller
@RequestMapping("/payment")
public class PaymentController {
    
    @Autowired
    private PaymentService paymentService;
    
    @Autowired
    private XssFilter xssFilter;
    
    private final List<PaymentRequest> paymentRequests = new CopyOnWriteArrayList<>();
    
    @GetMapping("/create")
    public String showPaymentForm(Model model) {
        model.addAttribute("paymentRequest", new PaymentRequest());
        return "payment-form";
    }
    
    @PostMapping("/process")
    public String processPayment(@ModelAttribute("paymentRequest") PaymentRequest request,
                                RedirectAttributes redirectAttributes) {
        
        // 模拟多层过滤逻辑
        if (!PaymentValidator.isValidAmount(request.getAmount())) {
            redirectAttributes.addFlashAttribute("error", "Invalid amount");
            return "redirect:/payment/create";
        }
        
        // 存储前进行XSS过滤（存在绕过漏洞）
        String safeMemo = xssFilter.filter(request.getMemo());
        
        // 特殊处理包含script标签的输入（存在缺陷）
        if (safeMemo.contains("<script>")) {
            safeMemo = safeMemo.replace("<script>", "<scr_ipt>")
                               .replace("</script>", "</scr_ipt>");
        }
        
        PaymentRequest processedRequest = new PaymentRequest();
        processedRequest.setAmount(request.getAmount());
        processedRequest.setMemo(safeMemo);
        processedRequest.setUserId(request.getUserId());
        
        paymentRequests.add(processedRequest);
        
        // 调用服务层处理支付
        Mono<PaymentResponse> response = paymentService.processPayment(request);
        
        redirectAttributes.addFlashAttribute("paymentId", response.block().getId());
        return "redirect:/payment/confirm";
    }
    
    @GetMapping("/confirm")
    public String confirmPayment(Model model) {
        model.addAttribute("payments", paymentRequests);
        return "payment-confirm";
    }
    
    @GetMapping("/details")
    public String getPaymentDetails(@RequestParam("id") String paymentId,
                                    Model model) {
        // 查找支付记录（模拟数据库查询）
        PaymentRequest request = paymentRequests.stream()
            .filter(p -> p.getId().equals(paymentId))
            .findFirst()
            .orElseThrow();
            
        // 构建JSONP响应（存在漏洞）
        String jsonpCallback = request.getMemo(); // 使用用户输入作为回调函数名
        String jsonResponse = String.format("%s({\\"status\\":\\"success\\",\\"memo\\":\\"%s\\"});",
                                jsonpCallback, request.getMemo());
        
        model.addAttribute("paymentScript", jsonResponse);
        return "payment-details";
    }
}

// Thymeleaf模板（payment-details.html）
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Payment Details</title>
</head>
<body>
    <div id="payment-info">
        <!-- 存在漏洞的脚本注入点 -->
        <script th:inline="text">
            /*<![CDATA[*/
            document.write('[[${paymentScript}]]');
            /*]]>*/
        </script>
    </div>
</body>
</html>
*/