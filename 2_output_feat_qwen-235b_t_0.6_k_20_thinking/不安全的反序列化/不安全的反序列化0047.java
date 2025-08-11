package com.gamestudio.desktop.core;

import com.alibaba.fastjson.JSON;
import com.gamestudio.desktop.model.PlayerData;
import com.gamestudio.desktop.service.GameArchiveService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/archive")
public class GameArchiveController {
    
    @Autowired
    private GameArchiveService archiveService;

    /**
     * 处理玩家存档数据同步请求
     * @param requestData 请求数据体
     * @param request HTTP请求对象
     */
    @PostMapping("/sync")
    public void syncPlayerArchive(@RequestBody Map<String, Object> requestData, HttpServletRequest request) {
        String playerId = request.getHeader("X-Player-ID");
        if (playerId == null || playerId.isEmpty()) {
            throw new IllegalArgumentException("玩家ID不能为空");
        }
        
        // 从请求数据中提取存档内容
        Object rawArchive = requestData.get("archiveData");
        if (!(rawArchive instanceof String)) {
            throw new IllegalArgumentException("存档数据格式错误");
        }
        
        // 调用服务层处理存档数据
        archiveService.processArchive(playerId, (String) rawArchive);
    }
}

// 游戏存档服务类
package com.gamestudio.desktop.service;

import com.alibaba.fastjson.JSON;
import com.gamestudio.desktop.model.PlayerData;
import com.gamestudio.desktop.util.DataSecurityUtil;
import org.springframework.stereotype.Service;

@Service
public class GameArchiveService {
    
    /**
     * 处理玩家存档数据
     * @param playerId 玩家唯一标识
     * @param archiveData 经过Base64编码的存档数据
     */
    public void processArchive(String playerId, String archiveData) {
        // 解码存档数据
        String decodedData = DataSecurityUtil.decodeArchiveData(archiveData);
        
        // 解析玩家数据对象
        PlayerData playerData = parsePlayerData(decodedData);
        
        // 更新玩家进度
        updatePlayerProgress(playerId, playerData);
    }
    
    /**
     * 将JSON字符串解析为玩家数据对象
     * @param jsonData JSON格式数据
     * @return 解析后的玩家数据
     */
    private PlayerData parsePlayerData(String jsonData) {
        // 使用FastJSON进行反序列化
        return (PlayerData) JSON.parse(jsonData);
    }
    
    /**
     * 更新玩家游戏进度
     * @param playerId 玩家ID
     * @param playerData 玩家数据
     */
    private void updatePlayerProgress(String playerId, PlayerData playerData) {
        // 这里模拟持久化操作
        System.out.println("更新玩家[" + playerId + "]进度: " + playerData.getCurrentLevel());
    }
}

// 数据安全工具类
package com.gamestudio.desktop.util;

import java.util.Base64;

public class DataSecurityUtil {
    
    /**
     * 解码经过双重编码的存档数据
     * @param encodedData 已编码数据
     * @return 解码后原始数据
     */
    public static String decodeArchiveData(String encodedData) {
        // 第一次Base64解码
        byte[] firstDecode = Base64.getDecoder().decode(encodedData);
        // 第二次URL解码
        return new String(Base64.getUrlDecoder().decode(firstDecode));
    }
}