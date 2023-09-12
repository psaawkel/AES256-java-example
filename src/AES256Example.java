import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class AES256Example {

    public static void main(String[] args) throws Exception {

        String salt = "29808jd29dj3298d8923d92j3dj";
        String message = "Secret message";
        String key = "1bej3h2je98jd8j287h9dh8y32d8h2893hd92h3d872dh972h932hd8902h92hd9h239d88293d8932d89289jdj9d";

        String encrypted = encrypt(key, salt + message);

        String decrypted = decrypt(key, encrypted);

        // Display the results
        System.out.println("Original Text: " + message);
        System.out.println("Encrypted Text (Base64): " + encrypted);
        if(decrypted.startsWith(salt)) {
            System.out.println("SALT OK: " + decrypted);
            decrypted = decrypted.substring(salt.length());
        }
        System.out.println("Decrypted Text: " + decrypted);
    }

    static String encrypt(String key, String data) throws Exception {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] inputBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] hash = digest.digest(inputBytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");

        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        Cipher encryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, iv));
        byte[] ciphertext = encryptCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        byte[] complete = new byte[iv.length+ciphertext.length];

        System.arraycopy(iv, 0, complete, 0, iv.length);
        System.arraycopy(ciphertext, 0, complete, iv.length, ciphertext.length);

        String encryptedBase64 = Base64.getEncoder().encodeToString(complete);

        return encryptedBase64;
    }

    static String decrypt(String key, String ciphertext) throws Exception{

        byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
        byte[] iv = new byte[12];
        System.arraycopy(ciphertextBytes,0,iv,0,12);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] inputBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] hash = digest.digest(inputBytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(hash, "AES");

        byte[] ciphered = new byte[ciphertextBytes.length-12];
        System.arraycopy(ciphertextBytes,12,ciphered,0,ciphertextBytes.length-12);

        Cipher decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new GCMParameterSpec(128, iv));
        byte[] decryptedBytes = decryptCipher.doFinal(ciphered);

        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

        return decryptedText;
    }

}