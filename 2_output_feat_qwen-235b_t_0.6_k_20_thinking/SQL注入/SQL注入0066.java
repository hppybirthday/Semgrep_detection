package com.example.ml.controller;

import com.example.ml.service.VectorSearchService;
import com.example.ml.dto.SearchRequest;
import com.example.ml.dto.SearchResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/vector")
public class VectorSearchController {
    @Autowired
    private VectorSearchService vectorSearchService;

    @PostMapping("/search")
    public SearchResult search(@RequestBody SearchRequest request) {
        // 校验输入格式（业务规则）
        if (request.getQueryText() == null || request.getQueryText().isEmpty()) {
            throw new IllegalArgumentException("查询内容不能为空");
        }
        
        // 调用搜索服务
        return vectorSearchService.performSearch(
            request.getQueryText(),
            request.getSortField(),
            request.getOrder()
        );
    }
}

// --------------------------------------

package com.example.ml.service;

import com.example.ml.mapper.VectorMapper;
import com.example.ml.dto.SearchResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VectorSearchService {
    @Autowired
    private VectorMapper vectorMapper;

    public SearchResult performSearch(String queryText, String sortField, String order) {
        // 预处理排序参数（业务逻辑）
        String safeSort = "CREATE_TIME";
        if (sortField != null && !sortField.isEmpty()) {
            safeSort = sortField.toUpperCase();
        }
        
        // 执行数据库查询
        List<VectorRecord> results = vectorMapper.searchVectors(
            queryText,
            safeSort,
            "ASC".equals(order) ? "ASC" : "DESC"
        );
        
        return new SearchResult(results.size(), results);
    }
}

// --------------------------------------

package com.example.ml.mapper;

import com.example.ml.dto.VectorRecord;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

@Mapper
public interface VectorMapper {
    @Select({"<script>",
      "SELECT * FROM vector_data WHERE MATCH (content) AGAINST (${queryText} IN BOOLEAN MODE)",
      "ORDER BY ${sortField} ${order}",
      "LIMIT 100",
      "</script>"})
    List<VectorRecord> searchVectors(
        @Param("queryText") String queryText,
        @Param("sortField") String sortField,
        @Param("order") String order
    );
}

// --------------------------------------

package com.example.ml.dto;

import lombok.Data;

@Data
public class SearchRequest {
    private String queryText;
    private String sortField;
    private String order;
}

// --------------------------------------

package com.example.ml.dto;

import lombok.Data;

import java.util.List;

@Data
public class SearchResult {
    private int total;
    private List<VectorRecord> records;

    public SearchResult(int total, List<VectorRecord> records) {
        this.total = total;
        this.records = records;
    }
}

// --------------------------------------

package com.example.ml.dto;

import lombok.Data;

@Data
public class VectorRecord {
    private String id;
    private String content;
    private double similarity;
}