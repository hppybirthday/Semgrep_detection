package com.example.crawler;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.engine.PageQuery;
import org.beetl.sql.starter.MapperFactory;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.List;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/crawlers")
class CrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @GetMapping
    public PageQuery<Crawler> list(@RequestParam int pageNum,
                                    @RequestParam int pageSize,
                                    @RequestParam String sortField,
                                    @RequestParam String sortOrder) {
        return crawlerService.getCrawlers(pageNum, pageSize, sortField, sortOrder);
    }
}

@Service
class CrawlerService {
    @Autowired
    private CrawlerDAO crawlerDAO;

    public PageQuery<Crawler> getCrawlers(int pageNum, int pageSize, String sortField, String sortOrder) {
        PageQuery<Crawler> pageQuery = new PageQuery<>();
        pageQuery.setPageNumber(pageNum);
        pageQuery.setPageSize(pageSize);
        // 漏洞点：直接拼接排序参数
        pageQuery.setOrderBy(sortField + " " + sortOrder);
        crawlerDAO.queryCrawlersByPage(pageQuery);
        return pageQuery;
    }
}

@Mapper
interface CrawlerDAO {
    void queryCrawlersByPage(PageQuery<Crawler> pageQuery);
}

class Crawler {
    private Long id;
    private String url;
    private String status;
    // getters and setters
}

// BeetlSQL Mapper XML（简化表示）
/*
<select id="queryCrawlersByPage">
    SELECT * FROM crawlers
    <if test="pageQuery.orderBy != null">
        ORDER BY ${pageQuery.orderBy}  <!-- 漏洞点：使用${}导致SQL注入 -->
    </if>
</select>
*/