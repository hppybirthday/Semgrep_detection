package com.example.app.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.example.app.model.Favorite;
import com.example.app.service.FavoriteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 用户收藏列表查询接口
 * 提供根据客户端ID和排序规则查询收藏数据的功能
 */
@RestController
@RequestMapping("/favorites")
public class FavoriteController {
    @Autowired
    private FavoriteService favoriteService;

    @GetMapping("/list")
    public List<Favorite> getFavorites(
        @RequestParam(required = false) String clientIds,
        @RequestParam(required = false) String sortField) {
        return favoriteService.getFavorites(clientIds, sortField);
    }
}

// 业务逻辑层
@Service
class FavoriteService {
    @Autowired
    private FavoriteMapper favoriteMapper;

    /**
     * 查询用户收藏数据
     * @param clientIds 客户端ID集合（逗号分隔）
     * @param sortField 排序字段
     */
    public List<Favorite> getFavorites(String clientIds, String sortField) {
        QueryWrapper<Favorite> queryWrapper = new QueryWrapper<>();
        
        if (clientIds != null && !clientIds.isEmpty()) {
            String[] idArray = clientIds.split(",");
            // 构造IN查询条件
            String inClause = "('" + String.join("','", idArray) + "')";
            queryWrapper.apply("client_id IN " + inClause);
        }

        // 处理排序逻辑
        if (sortField != null && !sortField.isEmpty()) {
            // 动态拼接排序字段
            String orderByClause = "create_time " + sortField;
            queryWrapper.orderBy(true, orderByClause);
        }

        return favoriteMapper.selectList(queryWrapper);
    }
}