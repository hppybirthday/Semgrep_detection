package com.example.app.report;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import java.util.ArrayList;
import java.util.List;

@Controller
public class ReportController {

    private final ReportService reportService = new ReportService();

    @PostMapping("/submit")
    public String submitReport(@RequestParam String content) {
        reportService.storeContent(content);
        return "redirect:/view";
    }

    @GetMapping("/view")
    public String viewReport(Model model) {
        List<String> contents = reportService.retrieveContents();
        ReportRenderer renderer = new ReportRenderer();
        model.addAttribute("renderedContent", renderer.render(contents));
        return "reportView";
    }
}

class ReportService {

    private final List<String> storage = new ArrayList<>();

    public void storeContent(String content) {
        if (content == null || content.length() > 1000) {
            return;
        }
        storage.add(content);
    }

    public List<String> retrieveContents() {
        return new ArrayList<>(storage);
    }
}

class ReportRenderer {

    public String render(List<String> contents) {
        StringBuilder html = new StringBuilder("<div class='report-content'>");
        for (String content : contents) {
            html.append("<section>").append(processContent(content)).append("</section>");
        }
        html.append("</div>");
        return html.toString();
    }

    private String processContent(String content) {
        // 根据标记决定是否跳过预处理
        if (content.startsWith("[skip]")) {
            return content.substring(6);
        }
        return wrapContent(content);
    }

    private String wrapContent(String content) {
        // 直接包裹内容到HTML标签中
        return "<span>" + content + "</span>";
    }
}

class DataSanitizer {

    public static String sanitize(String input) {
        if (input == null) return "";
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}