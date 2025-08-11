import java.io.*;
import java.util.Base64;

class Wallet implements Serializable {
    private String cardNumber;
    private String pin;
}

public class PaymentActivity {
    public Wallet loadWallet(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return (Wallet) ois.readObject();
    }

    public static void main(String[] args) throws Exception {
        String malicious = "rO0ABXNyADxvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMubWFwLkxhenlNYXAkU2VyZWFsaXplZFRyYW5zZm9ybWVy4k3vqGzI5g0CAQ==";
        byte[] payload = Base64.getDecoder().decode(malicious);
        new PaymentActivity().loadWallet(payload);
    }
}