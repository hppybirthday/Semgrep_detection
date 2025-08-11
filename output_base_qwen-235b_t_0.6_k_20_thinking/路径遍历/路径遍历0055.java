import javax.script.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class GameScriptLoader {
    private static final String BASE_SCRIPT_PATH = "./game_scripts/";
    private ScriptEngineManager manager;
    private ScriptEngine engine;

    public GameScriptLoader() {
        manager = new ScriptEngineManager();
        engine = manager.getEngineByName("JavaScript");
        initializeBaseScript();
    }

    private void initializeBaseScript() {
        try {
            // 动态生成基础脚本类
            String scriptClass = "function GameScript() {\
    this.execute = function() {\
        print('Default script executed');\
    }\
}";
            engine.eval(scriptClass);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void loadCustomScript(String scriptName) {
        try {
            // 路径遍历漏洞点：未清理用户输入
            Path scriptPath = Paths.get(BASE_SCRIPT_PATH + scriptName);
            
            // 动态加载外部脚本
            if (Files.exists(scriptPath)) {
                Reader reader = new FileReader(scriptPath.toFile());
                engine.eval(reader);
                reader.close();
                
                // 反射调用脚本方法
                Object scriptObj = engine.eval("new GameScript()");
                engine.callMethod(scriptObj, "execute");
            } else {
                System.out.println("Script not found: " + scriptName);
            }
        } catch (Exception e) {
            System.err.println("Script loading failed: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        GameScriptLoader loader = new GameScriptLoader();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== Game Script Loader ===");
        System.out.print("Enter script name to load: ");
        String userInput = scanner.nextLine();
        
        // 元编程特性：动态执行用户指定脚本
        loader.loadCustomScript(userInput);
        scanner.close();
    }
}