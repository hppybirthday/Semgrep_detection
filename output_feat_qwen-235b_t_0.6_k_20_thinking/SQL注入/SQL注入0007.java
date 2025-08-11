package com.gamestudio.ranking;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// 领域实体
class PlayerRank {
    private String playerName;
    private int score;
    private int level;
    // 省略getter/setter
}

// Mapper层
interface RankingMapper extends BaseMapper<PlayerRank> {
    @Select("SELECT * FROM player_rank ORDER BY ${sortColumn} ${sortOrder}")
    List<PlayerRank> getRankings(@Param("sortColumn") String sortColumn, 
                               @Param("sortOrder") String sortOrder);
}

// Service层
class RankingService extends ServiceImpl<RankingMapper, PlayerRank> {
    public List<PlayerRank> fetchRankings(String sortColumn, String sortOrder) {
        return baseMapper.getRankings(sortColumn, sortOrder);
    }
}

// Controller层
@RestController
@RequestMapping("/api/rankings")
class RankingController {
    @Autowired
    private RankingService rankingService;

    @GetMapping
    public List<PlayerRank> getRankings(
        @RequestParam(defaultValue = "score") String sortColumn,
        @RequestParam(defaultValue = "DESC") String sortOrder) {
        // 漏洞点：直接传递用户输入到SQL拼接
        return rankingService.fetchRankings(sortColumn, sortOrder);
    }
}

/*
漏洞示例：
正常请求：/api/rankings?sortColumn=score&sortOrder=DESC
攻击请求：/api/rankings?sortColumn=score;DROP TABLE player_rank;--&sortOrder=DESC
MyBatis生成的SQL会变成：SELECT * FROM player_rank ORDER BY score;DROP TABLE player_rank;-- DESC
导致数据表被删除
*/