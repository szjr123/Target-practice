import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

publicclass Main {
    public static String encrypt(String str, String str2) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(str2.getBytes());
            keyGenerator.init(128, secureRandom);
            SecretKeySpec secretKeySpec = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(1, secretKeySpec);
            return DatatypeConverter.printHexBinary(cipher.doFinal(str.getBytes()));
        } catch (Exception e) {
            e.printStackTrace();
            return"";
        }
    }

    public static void main(String[] args) {
        System.out.println(encrypt("1;1;"+System.currentTimeMillis(),"密码"));
    }
}