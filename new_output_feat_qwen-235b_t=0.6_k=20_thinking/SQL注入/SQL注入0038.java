package com.gamestudio.leaderboard.controller;

import com.gamestudio.leaderboard.service.PlayerService;
import com.gamestudio.leaderboard.model.Player;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/leaderboard")
public class PlayerRankController {
    @Autowired
    private PlayerService playerService;

    @GetMapping("/topPlayers")
    @ResponseBody
    public List<Player> getTopPlayers(@RequestParam(defaultValue = "score") String sortBy,
                                      @RequestParam(defaultValue = "desc") String order) {
        // 通过组合排序字段和排序方式构造动态SQL
        String sortCondition = sortBy + " " + order;
        return playerService.getTopPlayers(sortCondition);
    }
}

package com.gamestudio.leaderboard.service;

import com.gamestudio.leaderboard.mapper.PlayerMapper;
import com.gamestudio.leaderboard.model.Player;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PlayerService {
    @Autowired
    private PlayerMapper playerMapper;

    public List<Player> getTopPlayers(String sortCondition) {
        // 错误地将排序条件直接拼接到SQL中
        // 看似安全的字符串处理但存在绕过可能
        if (sortCondition.contains(";") || sortCondition.contains("--")) {
            throw new IllegalArgumentException("Invalid sort condition");
        }
        return playerMapper.findTopPlayers(sortCondition);
    }
}

package com.gamestudio.leaderboard.mapper;

import com.gamestudio.leaderboard.model.Player;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Mapper;
import java.util.List;

@Mapper
public interface PlayerMapper {
    // 使用MyBatis注解但错误地拼接排序条件
    @Select({"<script>",
            "SELECT * FROM players ORDER BY",
            "<if test='sortCondition != null'>",
            "${sortCondition}",  // 危险的变量替换方式
            "</if>",
            "LIMIT 10"})
    List<Player> findTopPlayers(@Param("sortCondition") String sortCondition);
}

package com.gamestudio.leaderboard.model;

public class Player {
    private Long id;
    private String username;
    private Integer score;
    private Integer level;
    // getters and setters
}

// MyBatis配置类（简化版）
@Configuration
public class MyBatisConfig {
    // 实际配置内容省略
}