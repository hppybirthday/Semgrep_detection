import java.io.*;
import java.lang.reflect.Method;
import java.util.Base64;

// 玩家数据类（存在漏洞的可序列化对象）
class PlayerData implements Serializable {
    private String playerName;
    private int health;
    private transient Method callback;

    public PlayerData(String name, int hp) {
        this.playerName = name;
        this.health = hp;
    }

    // 元编程：通过反射动态执行方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        try {
            in.defaultReadObject();
            Class<?> clazz = Class.forName("java.lang.Runtime");
            Method method = clazz.getMethod("exec", String.class);
            // 模拟动态执行恶意代码（攻击者可构造恶意序列化数据触发）
            if (callback != null) callback.invoke(null, "calc");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

// 游戏存档管理类
class GameArchive {
    // 不安全的反序列化操作（漏洞点）
    public static PlayerData loadGame(byte[] data) {
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            return (PlayerData) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] saveGame(PlayerData data) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(data);
            return bos.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}

// 恶意数据生成器（攻击面示例）
class MaliciousPayload {
    static byte[] generateEvilData() throws Exception {
        // 使用反射构造恶意对象（元编程特性）
        Class<?> tplClass = Class.forName("javax.script.ScriptEngineManager");
        Method method = tplClass.getMethod("eval", String.class);
        
        // 创建动态代理对象（元编程核心）
        Object proxy = java.lang.reflect.Proxy.newProxyInstance(
            tplClass.getClassLoader(),
            new Class[]{tplClass},
            (proxy1, method1, args) -> {
                if (method1.getName().equals("eval")) {
                    Runtime.getRuntime().exec("calc");
                }
                return null;
            }
        );
        
        // 序列化恶意对象
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(proxy);
        return bos.toByteArray();
    }
}

// 游戏启动器
public class GameLauncher {
    public static void main(String[] args) throws Exception {
        // 正常存档流程
        PlayerData saveData = new PlayerData("Hero", 100);
        byte[] archive = GameArchive.saveGame(saveData);
        
        // 模拟加载正常存档
        System.out.println("[+] 加载正常存档...");
        PlayerData loadData = GameArchive.loadGame(archive);
        System.out.println("玩家名称: " + loadData.playerName);
        
        // 模拟攻击者注入恶意数据
        System.out.println("\
[!] 注入恶意存档...");
        byte[] evilData = MaliciousPayload.generateEvilData();
        System.out.println("已生成恶意数据: " + Base64.getEncoder().encodeToString(evilData).substring(0, 20) + "...");
        
        // 触发漏洞（实际中可能通过文件/网络传输）
        GameArchive.loadGame(evilData);
    }
}