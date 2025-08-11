package com.gamestudio.admanager.controller;

import com.gamestudio.admanager.service.AdService;
import com.gamestudio.admanager.model.Advert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/ads")
public class AdManagementController {
    @Autowired
    private AdService adService;

    @GetMapping("/list")
    public String listAds(Model model) {
        List<Advert> ads = adService.getAllAds();
        model.addAttribute("ads", ads);
        return "ad-list";
    }

    @GetMapping("/create")
    public String showCreateForm(Model model) {
        model.addAttribute("advert", new Advert());
        return "create-ad";
    }

    @PostMapping("/create")
    public String createAdvert(@ModelAttribute("advert") Advert advert) {
        // 漏洞点：直接存储用户输入内容
        adService.saveAdvert(advert);
        return "redirect:/ads/list";
    }

    @GetMapping("/{id}")
    public String viewAd(@PathVariable("id") Long id, Model model) {
        Advert advert = adService.getAdvertById(id);
        // 漏洞点：直接传递未净化的内容到模板
        model.addAttribute("content", advert.getContent());
        return "view-ad";
    }
}

package com.gamestudio.admanager.service;

import com.gamestudio.admanager.model.Advert;
import com.gamestudio.admanager.repository.AdRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AdService {
    @Autowired
    private AdRepository adRepository;

    public List<Advert> getAllAds() {
        return adRepository.findAll();
    }

    public Advert getAdvertById(Long id) {
        return adRepository.findById(id).orElseThrow();
    }

    public void saveAdvert(Advert advert) {
        // 误导性代码：看似有安全处理但实际无效
        if (advert.getContent().contains("<script>")) {
            // 错误的清理逻辑：仅移除标签名但保留脚本内容
            advert.setContent(advert.getContent().replace("<script>", "<scr_ipt>").replace("</script>", "</scr_ipt>"));
        }
        adRepository.save(advert);
    }
}

package com.gamestudio.admanager.template;

import org.springframework.stereotype.Component;
import org.thymeleaf.ITemplateEngine;
import org.thymeleaf.context.Context;

@Component
public class AdTemplateRenderer {
    private final ITemplateEngine templateEngine;

    public AdTemplateRenderer(ITemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    public String renderAdContent(String rawContent) {
        Context context = new Context();
        // 漏洞点：使用不安全的变量注入方式
        context.setVariable("content", rawContent);
        // 使用text模板模式绕过HTML转义
        return templateEngine.process("ad-template", context, "text/html");
    }
}

package com.gamestudio.admanager.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "game_ads")
public class Advert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String content;
}

// Thymeleaf模板(view-ad.html)：
// <div class="ad-content">
//   <p th:text="${content}"></p>  <!-- 漏洞触发点 -->
// </div>