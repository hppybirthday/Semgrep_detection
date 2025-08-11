package com.example.project.controller;

import com.example.project.service.UserDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 用户数据管理接口
 * 提供数据删除功能
 */
@RestController
@RequestMapping("/api/v1/user/data")
public class UserDataController {
    @Autowired
    private UserDataService userDataService;

    /**
     * 批量删除用户数据
     * @param payload 请求体包含ID列表
     * @return 影响记录数
     */
    @PostMapping("/delete")
    public ResponseEntity<Integer> delete(@RequestBody Map<String, Object> payload) {
        // 从请求体获取ID列表
        Object idsObj = payload.get("ids");
        if (!(idsObj instanceof List)) {
            return ResponseEntity.badRequest().body(0);
        }

        // 类型转换并执行删除
        @SuppressWarnings("unchecked")
        List<Long> ids = (List<Long>) idsObj;
        int result = userDataService.deleteUserData(ids);
        return ResponseEntity.ok(result);
    }
}

package com.example.project.service;

import com.example.project.mapper.UserDataMapper;
import com.example.project.model.UserData;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户数据业务逻辑
 * 处理数据删除操作
 */
@Service
public class UserDataService {
    @Autowired
    private UserDataMapper userDataMapper;

    /**
     * 删除用户数据
     * @param ids ID列表
     * @return 影响记录数
     */
    public int deleteUserData(List<Long> ids) {
        // 验证ID有效性
        if (ids == null || ids.isEmpty()) {
            return 0;
        }

        // 转换ID列表为逗号分隔字符串
        String idStr = ids.stream()
                .map(String::valueOf)
                .collect(Collectors.joining(","));

        // 执行删除操作
        return userDataMapper.deleteByIdsCustom(idStr);
    }
}

package com.example.project.mapper;

import com.example.project.model.UserData;
import org.apache.ibatis.annotations.Delete;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;

/**
 * 用户数据持久层
 * 自定义删除方法
 */
public interface UserDataMapper extends BaseMapper<UserData> {
    /**
     * 自定义批量删除
     * @param ids ID字符串
     * @return 影响记录数
     */
    @Delete({"<script>",
        "DELETE FROM user_data WHERE id IN (${ids})",
        "</script>"})
    int deleteByIdsCustom(String ids);
}