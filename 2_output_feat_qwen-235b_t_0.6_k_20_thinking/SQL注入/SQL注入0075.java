package com.example.crawler.controller;

import com.example.crawler.service.DataSearchService;
import com.example.crawler.dto.SearchRequest;
import com.example.crawler.common.ApiResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/search")
public class DataSearchController {
    @Autowired
    private DataSearchService dataSearchService;

    /**
     * 搜索接口支持动态条件组合查询
     * @param request 搜索条件请求体
     * @return 查询结果
     */
    @PostMapping("/dynamic")
    public ApiResponse<List<?>> dynamicSearch(@RequestBody SearchRequest request) {
        List<?> results = dataSearchService.performSearch(
            request.getQueryText(),
            request.getPageNum(),
            request.getPageSize()
        );
        return ApiResponse.success(results);
    }
}

// ------------------------------------

package com.example.crawler.service;

import com.example.crawler.dao.SearchRepository;
import com.example.crawler.dto.SearchRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DataSearchService {
    @Autowired
    private SearchRepository searchRepository;

    /**
     * 执行搜索业务逻辑
     * @param queryText 查询关键词
     * @param pageNum 页码
     * @param pageSize 页大小
     * @return 查询结果
     */
    public List<?> performSearch(String queryText, int pageNum, int pageSize) {
        // 对输入进行简单长度校验
        if (queryText != null && queryText.length() > 200) {
            queryText = queryText.substring(0, 200);
        }
        
        // 构建排序字段（模拟多条件组合）
        String sortField = "relevance_score";
        if (pageNum < 1) pageNum = 1;
        if (pageSize < 1 || pageSize > 100) pageSize = 20;
        
        return searchRepository.searchData(queryText, sortField, pageNum, pageSize);
    }
}

// ------------------------------------

package com.example.crawler.dao;

import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class SearchRepository {
    @Autowired
    private SQLManager sqlManager;

    /**
     * 数据库查询实现
     * @param queryText 查询文本
     * @param sortField 排序字段
     * @param pageNum 页码
     * @param pageSize 页大小
     * @return 查询结果
     */
    public List<?> searchData(String queryText, String sortField, int pageNum, int pageSize) {
        String baseQuery = "SELECT * FROM search_index WHERE MATCH(content) AGAINST('${queryText}' IN BOOLEAN MODE)";
        
        // 动态添加排序条件
        String sortedQuery = baseQuery + " ORDER BY " + sortField + " DESC";
        
        // 分页处理
        int offset = (pageNum - 1) * pageSize;
        String finalQuery = sortedQuery + " LIMIT " + offset + "," + pageSize;
        
        // 执行查询（存在漏洞点）
        return sqlManager.execute(finalQuery, Map.class).getList();
    }
}