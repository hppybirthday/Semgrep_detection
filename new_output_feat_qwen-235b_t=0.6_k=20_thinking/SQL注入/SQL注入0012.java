package com.example.science.controller;

import com.example.science.service.SimulationService;
import com.example.science.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/simulation")
public class SimulationController {
    @Autowired
    private SimulationService simulationService;

    @DeleteMapping("/delete")
    public String deleteSimulations(@RequestBody DeleteRequest request) {
        if (request.getIds() == null || request.getIds().isEmpty()) {
            return "Invalid request: empty IDs";
        }
        
        // 检查是否为数字格式（存在绕过漏洞）
        for (String id : request.getIds()) {
            if (!id.matches("\\\\d+")) {
                return "Invalid ID format";
            }
        }
        
        try {
            simulationService.deleteSimulations(request.getIds());
            return "Deletion successful";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

package com.example.science.service;

import com.example.science.mapper.SimulationMapper;
import com.example.science.dto.DeleteRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SimulationService {
    @Autowired
    private SimulationMapper simulationMapper;

    public void deleteSimulations(List<String> simulationIds) {
        if (simulationIds == null || simulationIds.size() > 100) {
            throw new IllegalArgumentException("Invalid batch size");
        }
        
        // 构建逗号分隔的ID字符串
        StringBuilder idBuilder = new StringBuilder();
        for (String id : simulationIds) {
            if (idBuilder.length() > 0) {
                idBuilder.append(",");
            }
            idBuilder.append(id);
        }
        
        // 调用Mapper执行删除（存在SQL注入漏洞）
        simulationMapper.deleteSimulations(idBuilder.toString());
    }
}

package com.example.science.mapper;

import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface SimulationMapper {
    @Delete({"<script>",
      "DELETE FROM simulation_data WHERE id IN (${mainId})",
      "</script>"})
    void deleteSimulations(@Param("mainId") String mainId);
    
    // 用于验证ID存在的辅助查询（存在二次注入风险）
    @Select("SELECT COUNT(*) FROM simulation_data WHERE id = ${id}")
    int checkIdExists(@Param("id") String id);
}

// DTO类
package com.example.science.dto;

import java.util.List;

public class DeleteRequest {
    private List<String> ids;

    public List<String> getIds() {
        return ids;
    }

    public void setIds(List<String> ids) {
        this.ids = ids;
    }
}