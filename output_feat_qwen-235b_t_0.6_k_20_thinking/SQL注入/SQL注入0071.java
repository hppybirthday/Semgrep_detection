package com.gamestudio.achievement;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;
import java.util.Arrays;
import java.util.List;

// Vulnerable entity class
public class Achievement {
    private Integer id;
    private String playerName;
    private Integer score;
    // Getters and setters
}

// Mapper interface
interface AchievementMapper extends BaseMapper<Achievement> {}

// Service with SQL injection vulnerability
@Service
class AchievementService extends ServiceImpl<AchievementMapper, Achievement> {
    // Vulnerable method with SQL injection in batch delete
    public void deleteAchievements(String idList, String orderBy) {
        // Unsafe SQL construction with user input
        String query = "DELETE FROM achievements WHERE id IN (" + idList + ")";
        
        // Improper order by handling
        if (orderBy != null && !orderBy.isEmpty()) {
            query += " ORDER BY " + SqlUtil.escapeOrderBySql(orderBy);
        }
        
        // Direct SQL execution (simulated with MyBatis wrapper)
        QueryWrapper<Achievement> wrapper = new QueryWrapper<>();
        wrapper.apply(query); // Dangerous: Direct SQL injection point
        this.baseMapper.delete(wrapper);
    }
}

// Controller simulating user interaction
@RestController
@RequestMapping("/achievements")
class AchievementController {
    private final AchievementService achievementService;

    public AchievementController(AchievementService service) {
        this.achievementService = service;
    }

    @DeleteMapping("/batch")
    public ResponseEntity<String> batchDelete(@RequestParam String ids, 
                                              @RequestParam(required = false) String order) {
        // Simulate vulnerable call with user input
        achievementService.deleteAchievements(ids, order);
        return ResponseEntity.ok("Deleted achievements");
    }
}

// Insecure SQL utility class
class SqlUtil {
    // Incomplete escaping implementation
    static String escapeOrderBySql(String input) {
        // Only removes basic SQL keywords but allows advanced injection
        return input.replaceAll("(UNION|SELECT|DROP)", "");
    }
}

// Example usage scenario
/*
Attack example:
GET /achievements/batch?ids=1,2;+DROP+TABLE+achievements--&order=score;+DROP+TABLE+users
Final SQL: DELETE FROM achievements WHERE id IN (1,2; DROP TABLE achievements--) ORDER BY score; DROP TABLE users
*/