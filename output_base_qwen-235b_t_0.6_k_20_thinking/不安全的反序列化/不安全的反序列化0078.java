import java.io.*;
import java.util.*;

class User implements Serializable {
    String username;
    transient String password;
    User(String u, String p) {
        username = u;
        password = p;
    }
}

public class LoginActivity extends Activity {
    private void saveUser() {
        try {
            ObjectOutputStream out = new ObjectOutputStream(
                openFileOutput("user.dat", MODE_PRIVATE));
            out.writeObject(new User("admin", "secret"));
            out.close();
        } catch (Exception e) {}
    }

    private void loadUser() {
        try {
            ObjectInputStream in = new ObjectInputStream(
                openFileInput("user.dat"));
            User user = (User) in.readObject();
            in.close();
            System.out.println("Welcome " + user.username);
        } catch (Exception e) {}
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        saveUser();
        loadUser();
    }
}