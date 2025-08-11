package com.example.crawler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/crawler")
public class CrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping("/data")
    public List<CrawlerData> getData(@RequestParam String source) {
        return crawlerService.findBySource(source);
    }

    @PostMapping("/data")
    public void saveData(@RequestParam String content, @RequestParam String source) {
        crawlerService.saveData(content, source);
    }
}

@Service
class CrawlerService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<CrawlerData> findBySource(String source) {
        // SQL注入漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM crawled_data WHERE source = '" + source + "'";
        return jdbcTemplate.query(query, (rs, rowNum) ->
            new CrawlerData(rs.getString("content"), rs.getString("source"))
        );
    }

    public void saveData(String content, String source) {
        // SQL注入漏洞点：直接拼接SQL语句
        String query = "INSERT INTO crawled_data (content, source) VALUES ('" 
                     + content.replace("'", "''") + "', '" 
                     + source.replace("'", "''") + "')";
        jdbcTemplate.execute(query);
    }
}

class CrawlerData {
    private String content;
    private String source;

    public CrawlerData(String content, String source) {
        this.content = content;
        this.source = source;
    }

    // Getters and setters
    public String getContent() { return content; }
    public String getSource() { return source; }
}