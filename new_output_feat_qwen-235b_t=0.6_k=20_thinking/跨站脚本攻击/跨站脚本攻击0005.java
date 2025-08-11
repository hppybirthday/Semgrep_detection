package com.gamestudio.notice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.spring6.context.webmvc.SpringWebMvcThymeleafRequestContext;
import jakarta.persistence.*;
import java.util.List;

@SpringBootApplication
public class GameNoticeApplication {
    public static void main(String[] args) {
        SpringApplication.run(GameNoticeApplication.class, args);
    }
}

@Entity
class GameNotice {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String content;
    private String sanitizedContent;
    // 模拟业务逻辑中的冗余字段
    private boolean isProcessed = false;

    // Getters and setters
    public Long getId() { return id; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
    public String getSanitizedContent() { return sanitizedContent; }
    public void setSanitizedContent(String sanitizedContent) { this.sanitizedContent = sanitizedContent; }
}

interface GameNoticeRepository extends JpaRepository<GameNotice, Long> {
    List<GameNotice> findTop10ByOrderByIdDesc();
}

@Service
class GameNoticeService {
    private final GameNoticeRepository repository;

    public GameNoticeService(GameNoticeRepository repository) {
        this.repository = repository;
    }

    public List<GameNotice> getLatestNotices() {
        return repository.findTop10ByOrderByIdDesc();
    }

    public void publishNotice(String rawContent) {
        GameNotice notice = new GameNotice();
        // 模拟错误的安全处理：仅截断长度但未转义
        String processed = rawContent.length() > 200 ? rawContent.substring(0, 200) : rawContent;
        notice.setContent(processed);
        // 错误地复制内容而非转义
        notice.setSanitizedContent(processed);
        repository.save(notice);
    }
}

@RestController
@RequestMapping("/notice")
class GameNoticeController {
    private final GameNoticeService service;

    public GameNoticeController(GameNoticeService service) {
        this.service = service;
    }

    @PostMapping("/publish")
    public String publish(@RequestParam String content) {
        service.publishNotice(content);
        return "Notice published";
    }

    @GetMapping("/list")
    public String listNotices() {
        StringBuilder html = new StringBuilder("<div class='notices'>");
        for (GameNotice notice : service.getLatestNotices()) {
            // 漏洞点：直接拼接未转义内容
            html.append("<div class='notice'>")
                .append(notice.getSanitizedContent())
                .append("</div>");
        }
        html.append("</div>");
        return html.toString();
    }
}

// 模拟Thymeleaf模板错误使用
class NoticeTemplate {
    // 错误的模板处理逻辑
    public String renderNotice(GameNotice notice) {
        return "<div th:utext='${notice.content}'></div>"; // 不安全的模板指令
    }
}