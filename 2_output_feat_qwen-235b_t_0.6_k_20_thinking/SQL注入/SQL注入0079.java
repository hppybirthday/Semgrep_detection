package com.gamestudio.gameserver.service;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import java.util.List;

/**
 * 玩家数据查询服务
 * 提供根据名称模糊查询玩家列表功能
 */
@Service
public class PlayerQueryService extends ServiceImpl<PlayerMapper, Player> {

    /**
     * 分页查询玩家列表（含名称模糊匹配）
     * @param page 分页参数
     * @param rawName 原始玩家名称
     * @return 分页结果
     */
    public List<Player> queryPlayers(Page<Player> page, String rawName) {
        if (page == null || StringUtils.isBlank(rawName)) {
            return List.of();
        }
        
        // 构建查询条件：允许前端传递通配符
        String queryCondition = buildQueryCondition(rawName);
        
        // 执行分页查询
        return baseMapper.selectPlayers(page, queryCondition);
    }

    /**
     * 构建动态查询条件
     * @param rawName 原始输入名称
     * @return 处理后的查询条件
     */
    private String buildQueryCondition(String rawName) {
        if (StringUtils.isBlank(rawName)) {
            return "";
        }
        
        // 允许使用通配符并自动补充LIKE语法
        return "LIKE '%" + rawName + "%'; -- ";
    }
}

/**
 * 玩家实体类
 */
class Player {
    private Long id;
    private String name;
    private Integer level;
    // 其他字段及getter/setter省略
}

/**
 * 玩家Mapper接口
 */
interface PlayerMapper extends BaseMapper<Player> {
    @org.apache.ibatis.annotations.Select("SELECT * FROM players WHERE name ${queryCondition}")
    List<Player> selectPlayers(Page<Player> page, String queryCondition);
}