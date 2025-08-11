package com.example.vulnapp;

import org.springframework.web.bind.annotation.*;
import com.alibaba.fastjson.JSON;
import java.io.Serializable;

@RestController
@RequestMapping("/mock/dlglong")
public class VulnerableController {
    
    @PostMapping("/change2")
    public String changeStatus(@RequestParam String tug_status) {
        StatusDTO dto = JSON.parseObject(tug_status, StatusDTO.class);
        return "Status updated to: " + dto.getStatus();
    }
    
    @PostMapping("/getDdjhData")
    public String queryData(@RequestParam String superQueryParams) {
        QueryParams params = JSON.parseObject(superQueryParams, QueryParams.class);
        return "Querying with params: " + params.toString();
    }
    
    @PostMapping("/immediateSaveRow")
    public String saveRow(@RequestBody String payload) {
        DataRecord record = JSON.parseObject(payload, DataRecord.class);
        return "Saved record: " + record.toString();
    }
    
    static class StatusDTO implements Serializable {
        private String status;
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
    }
    
    static class QueryParams implements Serializable {
        private String filter;
        private int limit;
        public String getFilter() { return filter; }
        public void setFilter(String filter) { this.filter = filter; }
        public int getLimit() { return limit; }
        public void setLimit(int limit) { this.limit = limit; }
        public String toString() { return "Filter: " + filter + ", Limit: " + limit; }
    }
    
    static class DataRecord implements Serializable {
        private String id;
        private String content;
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
        public String toString() { return "ID: " + id + ", Content: " + content; }
    }
}