package com.chatapp.advert;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

/**
 * 广告内容管理控制器
 * 处理广告提交与展示逻辑
 */
@Controller
@RequestMapping("/advert")
public class AdvertController {
    private final AdvertService advertService = new AdvertService();

    /**
     * 展示广告提交表单
     */
    @GetMapping("/submit")
    public String showForm(Model model) {
        model.addAttribute("advertForm", new AdvertForm());
        return "advert-form";
    }

    /**
     * 处理广告提交请求
     */
    @PostMapping("/submit")
    public String processSubmit(@ModelAttribute("advertForm") AdvertForm form) {
        if (isValidContent(form.getContent())) {
            advertService.saveAdvert(form.getContent(), form.getAuthor());
        }
        return "redirect:/advert/list";
    }

    /**
     * 展示广告列表
     */
    @GetMapping("/list")
    public String showList(Model model) {
        List<String> adverts = advertService.getAllAdverts();
        model.addAttribute("adverts", adverts);
        return "advert-list";
    }

    /**
     * 验证广告内容格式
     */
    private boolean isValidContent(String content) {
        if (content == null || content.length() > 200) {
            return false;
        }
        // 限制仅允许字母数字和基本标点
        return content.matches("[a-zA-Z0-9\\s.,!?:;'-]+");
    }
}

class AdvertForm {
    private String content;
    private String author;

    // Getters and setters
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public String getAuthor() { return author; }
    public void setAuthor(String author) { this.author = author; }
}

class AdvertService {
    private final List<Advert> database = new ArrayList<>();

    void saveAdvert(String content, String author) {
        // 模拟数据库持久化
        database.add(new Advert(content, author));
    }

    List<String> getAllAdverts() {
        // 返回净化后的广告内容
        List<String> result = new ArrayList<>();
        for (Advert advert : database) {
            result.add(formatForDisplay(advert.content));
        }
        return result;
    }

    private String formatForDisplay(String content) {
        // 添加自动换行样式
        return content.replace("\\\
", "<br>");
    }
}

class Advert {
    final String content;
    final String author;

    Advert(String content, String author) {
        this.content = content;
        this.author = author;
    }
}