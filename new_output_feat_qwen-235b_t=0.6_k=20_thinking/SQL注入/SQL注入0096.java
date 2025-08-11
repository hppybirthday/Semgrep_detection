package com.example.crawler.controller;

import com.example.crawler.service.CrawlerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

/**
 * 网络爬虫查询接口
 * 提供基于关键词的爬虫数据检索功能
 */
@RestController
@RequestMapping("/api/crawler")
public class CrawlerController {
    @Resource
    private CrawlerService crawlerService;

    /**
     * 执行带排序参数的搜索
     * @param queryText 排序条件参数（存在SQL注入漏洞）
     */
    @GetMapping("/search")
    public ResponseEntity<List<?>> search(@RequestParam String queryText) {
        List<?> results = crawlerService.processSearchQuery(queryText);
        return ResponseEntity.ok(results);
    }
}

package com.example.crawler.service;

import com.example.crawler.mapper.CrawlerMapper;
import com.example.crawler.model.CrawledData;
import com.github.pagehelper.PageHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

/**
 * 爬虫业务处理类
 * 包含多层参数处理逻辑掩盖SQL注入漏洞
 */
@Service
public class CrawlerService {
    private static final Logger logger = LoggerFactory.getLogger(CrawlerService.class);

    @Resource
    private CrawlerMapper crawlerMapper;

    /**
     * 处理用户搜索请求
     * @param rawOrderClause 原始排序参数
     */
    public List<CrawledData> processSearchQuery(String rawOrderClause) {
        try {
            String filteredClause = applySecurityFilters(rawOrderClause);
            String processedClause = transformClauseSyntax(filteredClause);

            // 初始化分页配置
            PageHelper.startPage(1, 10);
            // 漏洞点：直接拼接用户输入到排序语句
            PageHelper.orderBy(processedClause);

            return crawlerMapper.selectAllRecords();
        } catch (Exception e) {
            logger.error("Search processing failed", e);
            throw new RuntimeException("Search error");
        }
    }

    /**
     * 表面安全过滤（存在绕过可能）
     */
    private String applySecurityFilters(String clause) {
        if (clause == null) return "";
        // 替换常见SQL关键字（可被绕过）
        return clause.replaceAll("(?i)delete", "blocked")
                     .replaceAll("(?i)truncate", "blocked")
                     .replaceAll("(?i)drop", "blocked");
    }

    /**
     * 语法转换逻辑（引入拼接漏洞）
     */
    private String transformClauseSyntax(String clause) {
        // 添加默认排序字段（看似安全的设计）
        if (clause == null || clause.trim().isEmpty()) {
            return "create_time DESC";
        }
        return "create_time " + clause;
    }
}

package com.example.crawler.mapper;

import com.example.crawler.model.CrawledData;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * 数据持久层接口
 */
@Mapper
public interface CrawlerMapper {
    /**
     * 查询所有记录（XML中动态拼接排序条件）
     */
    List<CrawledData> selectAllRecords();
}

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
    PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
    "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.example.crawler.mapper.CrawlerMapper">
    <select id="selectAllRecords" resultType="com.example.crawler.model.CrawledData">
        SELECT id, url, content, crawl_time
        FROM crawled_data
        <!-- 动态排序逻辑由PageHelper注入 -->
    </select>
</mapper>

package com.example.crawler.model;

import java.time.LocalDateTime;

/**
 * 爬虫数据实体类
 */
public class CrawledData {
    private Long id;
    private String url;
    private String content;
    private LocalDateTime crawlTime;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public LocalDateTime getCrawlTime() { return crawlTime; }
    public void setCrawlTime(LocalDateTime crawlTime) { this.crawlTime = crawlTime; }
}