package com.example.demo;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.Resource;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/cart")
public class CartController {
    @Resource
    private StringRedisTemplate redisTemplate;

    // 模拟移动客户端上传购物车数据
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file) {
        try {
            // 读取上传文件内容
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream()));
            StringBuilder jsonData = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                jsonData.append(line);
            }
            
            // 危险的反序列化操作（漏洞点）
            JSONObject cartData = JSON.parseObject(jsonData.toString());
            
            // 模拟业务逻辑：合并Redis中的购物车数据
            String userId = cartData.getString("userId");
            String redisKey = "cart:" + userId;
            
            // 从Redis获取现有购物车
            String existingCart = redisTemplate.opsForValue().get(redisKey);
            JSONObject mergedCart = existingCart == null ? 
                new JSONObject() : JSON.parseObject(existingCart);
                
            // 合并商品信息（触发反序列化漏洞）
            mergedCart.putAll(cartData.getJSONObject("items"));
            
            // 将合并后的购物车存回Redis
            redisTemplate.opsForValue().set(redisKey, mergedCart.toJSONString(), 
                30, TimeUnit.MINUTES);
            
            return "Cart updated successfully";
            
        } catch (Exception e) {
            return "Error processing cart data: " + e.getMessage();
        }
    }
    
    // 模拟商品详情接口（间接利用漏洞）
    @GetMapping("/product/{pid}")
    public String getProductDetail(@PathVariable String pid) {
        // 从Redis获取商品信息（可能已被污染）
        String productJson = redisTemplate.opsForValue().get("product:" + pid);
        if (productJson == null) {
            return "Product not found";
        }
        
        // 二次反序列化（扩大攻击面）
        JSONObject product = JSON.parseObject(productJson);
        return "Product Detail: " + product.getString("name");
    }
}