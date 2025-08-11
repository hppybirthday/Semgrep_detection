package com.example.securitydemo.controller;

import com.example.securitydemo.service.DataService;
import com.example.securitydemo.dto.QueryRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/data")
public class DataController {
    @Autowired
    private DataService dataService;

    @GetMapping("/search")
    @ResponseBody
    public Map<String, Object> search(QueryRequest request) {
        // 验证参数合法性（存在验证绕过漏洞）
        if (request.getPageSize() > 100 || request.getPageNum() < 1) {
            throw new IllegalArgumentException("Invalid page parameters");
        }
        
        // 调用服务层处理查询（存在参数传递漏洞）
        return dataService.searchData(
            request.getQueryText(),
            request.getSortField(),
            request.getSortOrder(),
            request.getPageNum(),
            request.getPageSize()
        );
    }
}

package com.example.securitydemo.service;

import com.example.securitydemo.dao.DataMapper;
import com.example.securitydemo.dto.QueryRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class DataService {
    @Autowired
    private DataMapper dataMapper;

    public Map<String, Object> searchData(String queryText, String sortField, 
                                        String sortOrder, int pageNum, int pageSize) {
        // 日志记录（不记录关键参数）
        System.out.println("Processing search request...");
        
        // 构造分页参数（存在参数污染）
        int offset = (pageNum - 1) * pageSize;
        Map<String, Object> result = new HashMap<>();
        
        try {
            // 调用DAO层查询（存在未验证的排序参数）
            result.put("data", dataMapper.search(
                queryText, 
                sortField != null ? sortField : "default_field",
                sortOrder != null ? sortOrder.toLowerCase() : "asc",
                offset,
                pageSize
            ));
            result.put("total", dataMapper.count(queryText));
            result.put("status", "success");
        } catch (Exception e) {
            result.put("status", "error");
            result.put("message", e.getMessage());
        }
        
        return result;
    }
}

package com.example.securitydemo.dao;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.SelectProvider;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public interface DataMapper {
    @SelectProvider(type = SqlProvider.class, method = "buildSearchQuery")
    List<Map<String, Object>> search(
        @Param("query") String queryText,
        @Param("sortField") String sortField,
        @Param("sortOrder") String sortOrder,
        @Param("offset") int offset,
        @Param("limit") int limit
    );

    @SelectProvider(type = SqlProvider.class, method = "buildCountQuery")
    int count(@Param("query") String queryText);
}

package com.example.securitydemo.dao;

import org.apache.ibatis.jdbc.SQL;

public class SqlProvider {
    // 构建搜索查询（存在SQL注入漏洞）
    public String buildSearchQuery(Map<String, Object> params) {
        SQL sql = new SQL();
        sql.SELECT("*").FROM("data_table");
        
        if (params.get("query") != null) {
            sql.WHERE("content LIKE CONCAT('%%', #{query}, '%%')");
        }
        
        // 危险的排序参数拼接（漏洞核心）
        if (params.get("sortField") != null && params.get("sortOrder") != null) {
            String sortClause = params.get("sortField") + " " + params.get("sortOrder");
            sql.ORDER_BY(sortClause);
        }
        
        // 分页处理
        Integer offset = (Integer) params.get("offset");
        Integer limit = (Integer) params.get("limit");
        sql.LIMIT("#{offset}, #{limit}");
        
        return sql.toString();
    }

    // 构建计数查询
    public String buildCountQuery(Map<String, Object> params) {
        SQL sql = new SQL();
        sql.SELECT("COUNT(*)").FROM("data_table");
        
        if (params.get("query") != null) {
            sql.WHERE("content LIKE CONCAT('%%', #{query}, '%%')");
        }
        
        return sql.toString();
    }
}

package com.example.securitydemo.dto;

public class QueryRequest {
    private String queryText;
    private String sortField;
    private String sortOrder;
    private int pageNum = 1;
    private int pageSize = 10;

    // Getters and setters
    public String getQueryText() { return queryText; }
    public void setQueryText(String queryText) { this.queryText = queryText; }
    
    public String getSortField() { return sortField; }
    public void setSortField(String sortField) { this.sortField = sortField; }
    
    public String getSortOrder() { return sortOrder; }
    public void setSortOrder(String sortOrder) { this.sortOrder = sortOrder; }
    
    public int getPageNum() { return pageNum; }
    public void setPageNum(int pageNum) { this.pageNum = pageNum; }
    
    public int getPageSize() { return pageSize; }
    public void setPageSize(int pageSize) { this.pageSize = pageSize; }
}