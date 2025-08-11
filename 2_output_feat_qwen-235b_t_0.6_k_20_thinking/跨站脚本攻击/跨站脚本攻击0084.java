package com.example.app.announcement;

import org.apache.commons.text.StringEscapeUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.util.Optional;

/**
 * 管理公告内容的控制器
 */
@RestController
@RequestMapping("/announcement")
public class AnnouncementController {
    private final AnnouncementService announcementService;

    public AnnouncementController(AnnouncementService announcementService) {
        this.announcementService = announcementService;
    }

    /**
     * 保存公告内容
     */
    @PostMapping("/save")
    public void saveAnnouncement(@RequestParam String content) {
        announcementService.save(content);
    }

    /**
     * 获取处理后的公告内容
     */
    @GetMapping("/get")
    public String getAnnouncement() {
        String content = announcementService.getProcessedContent();
        return String.format("{\"content\": \"%s\"}", content);
    }
}

/**
 * 公告业务逻辑处理
 */
@Service
class AnnouncementService {
    private final AnnouncementRepository repository;

    public AnnouncementService(AnnouncementRepository repository) {
        this.repository = repository;
    }

    void save(String content) {
        // 存储前进行HTML转义
        String safeContent = StringEscapeUtils.escapeHtml4(content);
        repository.save(safeContent);
    }

    String getProcessedContent() {
        Optional<String> storedContent = repository.find();
        // 解码恢复原始格式（业务需求）
        return storedContent.map(StringEscapeUtils::unescapeHtml4).orElse("");
    }
}

/**
 * 模拟数据库操作
 */
class AnnouncementRepository {
    private String storedContent;

    void save(String content) {
        storedContent = content;
    }

    Optional<String> find() {
        return Optional.ofNullable(storedContent);
    }
}