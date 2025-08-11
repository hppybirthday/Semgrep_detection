package com.example.crawler;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequestMapping("/api")
public class SpiderController {
    @Autowired
    private SpiderService spiderService;

    @GetMapping("/data")
    @ResponseBody
    public List<CrawledData> getData(@RequestParam String orderBy, @RequestParam String order) {
        return spiderService.fetchData(orderBy, order);
    }
}

interface SpiderService {
    List<CrawledData> fetchData(String orderBy, String order);
}

@Service
class SpiderServiceImpl implements SpiderService {
    @Autowired
    private DataMapper dataMapper;

    @Override
    public List<CrawledData> fetchData(String orderBy, String order) {
        String sort = "ORDER BY " + orderBy + " " + order;
        return dataMapper.queryData(sort);
    }
}

interface DataMapper {
    @Select("SELECT * FROM crawled_data ${sort}")
    List<CrawledData> queryData(@Param("sort") String sort);
}

class CrawledData {
    private Long id;
    private String content;
    // Getters and setters
}

// MyBatis XML Mapper
// <mapper namespace="com.example.crawler.DataMapper">
//    <select id="queryData" resultType="com.example.crawler.CrawledData">
//        SELECT * FROM crawled_data
//        <if test="sort != null">
//            ORDER BY ${sort}
//        </if>
//    </select>
// </mapper>