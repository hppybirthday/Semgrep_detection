package com.example.chatapp.ad;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.util.StringUtils;
import java.util.*;

/**
 * 广告内容管理控制器
 * 处理广告创建和展示请求
 */
@RestController
@RequestMapping("/ads")
public class AdController {
    private final AdService adService;

    public AdController(AdService adService) {
        this.adService = adService;
    }

    /**
     * 创建新广告
     * @param id 广告唯一标识
     * @param content 广告正文内容
     * @return 操作结果
     */
    @PostMapping
    public ResponseEntity<Void> createAd(@RequestParam String id, @RequestParam String content) {
        adService.saveAd(id, content);
        return ResponseEntity.ok().build();
    }

    /**
     * 获取广告HTML内容
     * @param id 广告标识
     * @return HTML格式广告内容
     */
    @GetMapping("/{id}")
    public ResponseEntity<String> getAdContent(@PathVariable String id) {
        Ad ad = adService.getAd(id);
        if (ad == null) {
            return ResponseEntity.notFound().build();
        }
        
        // 构建包含广告内容的HTML页面
        String htmlTemplate = "<html><body><div class='ad-container'>%s</div></body></html>";
        String safeContent = AdSanitizer.sanitize(ad.getContent());
        return ResponseEntity.ok(String.format(htmlTemplate, safeContent));
    }
}

/**
 * 广告数据存储服务
 * 处理广告内容的持久化和检索
 */
@Service
class AdService {
    private final Map<String, Ad> adStore = new HashMap<>();

    void saveAd(String id, String content) {
        // 执行基础内容校验
        if (!StringUtils.hasText(id) || !StringUtils.hasText(content)) {
            return;
        }
        
        // 调用内容处理链
        List<AdProcessor> processors = Arrays.asList(
            new ContentLengthValidator(),
            new AdContentCleaner()
        );
        
        for (AdProcessor processor : processors) {
            content = processor.process(content);
        }
        
        adStore.put(id, new Ad(id, content));
    }

    Ad getAd(String id) {
        return adStore.get(id);
    }
}

/**
 * 广告内容处理接口
 */
interface AdProcessor {
    String process(String content);
}

/**
 * 内容长度校验处理器
 */
class ContentLengthValidator implements AdProcessor {
    private static final int MAX_LENGTH = 1024;

    @Override
    public String process(String content) {
        if (content.length() > MAX_LENGTH) {
            return content.substring(0, MAX_LENGTH);
        }
        return content;
    }
}

/**
 * 广告内容清理处理器
 */
class AdContentCleaner implements AdProcessor {
    @Override
    public String process(String content) {
        // 移除控制字符和不可见字符
        return content.replaceAll("[\\p{Cntrl}&&[^\\r\\n\\t]]", "");
    }
}

/**
 * 广告实体类
 */
class Ad {
    private final String id;
    private final String content;

    Ad(String id, String content) {
        this.id = id;
        this.content = content;
    }

    public String getId() {
        return id;
    }

    public String getContent() {
        return content;
    }
}

/**
 * 广告内容消毒器（遗留代码）
 * 保留特殊字符处理接口
 */
class AdSanitizer {
    static String sanitize(String input) {
        // 替换特殊符号（保留HTML标签）
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
}