package util;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.mindrot.jbcrypt.BCrypt;


public class AesUtil {

    private static final Logger logger = LogManager.getLogger(AesUtil.class);

    // Generate a secret key of the specified size for AES encryption
    // Generate a secret key of the specified size for AES encryption
    public static SecretKey generateKey(int keySize) {
        try {
            logger.info("Generating secret key...");
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keySize);
            logger.info("Secret key generated successfully.");
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error generating secret key", e);
            throw new RuntimeException("Error generating secret key", e);
        }
    }

    // Derive a secret key from a password and salt using bcrypt
    public static SecretKey getKeyFromPassword(String password, String salt) throws IllegalArgumentException {
        logger.info("Deriving secret key from password...");
        // Generate a bcrypt hash from the password
        String hashedPassword = BCrypt.hashpw(password, salt);

        // Derive a secret key from the hashed password
        byte[] encodedKey = hashedPassword.getBytes(StandardCharsets.UTF_8);
        SecretKey secret = new SecretKeySpec(encodedKey, "AES");

        return secret;
    }

    // Generate a random initialization vector (IV)
    public static IvParameterSpec generateIv() {
        try {
            logger.info("Generating initialization vector (IV)...");
            byte[] iv = new byte[16]; // Use a 128-bit IV (16 bytes) for AES
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(iv);
            return new IvParameterSpec(iv);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error generating IV", e);
            throw new RuntimeException("Error generating IV", e);
        }
    }


    // Encrypt a string using the specified algorithm, key, and IV
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) {
        try {
            logger.info("Encrypting string...");
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            logger.error("Error encrypting string", e);
            throw new RuntimeException("Error encrypting string", e);
        }
    }


    // Decrypt a string using the specified algorithm, key, and IV
    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv) {
        try {
            logger.info("Decrypting string...");
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            logger.error("Error decrypting string", e);
            throw new RuntimeException("Error decrypting string", e);
        }
    }


    // Encrypt a file using the specified algorithm, key, and IV
    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) {
        try {
            logger.info("Encrypting file...");
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            try (FileInputStream inputStream = new FileInputStream(inputFile);
                 FileOutputStream outputStream = new FileOutputStream(outputFile)) {

                byte[] buffer = new byte[8192]; // Use a larger buffer size for better performance with larger files
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) {
                        outputStream.write(output);
                    }
                }
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    outputStream.write(outputBytes);
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            logger.error("Error encrypting file", e);
            throw new RuntimeException("Error encrypting file", e);
        }
    }


    // Encrypt a serializable object using the specified algorithm, key, and IV
    public static SealedObject encryptObject(String algorithm, Serializable object,
                                             SecretKey key, IvParameterSpec iv) {
        try {
            logger.info("Encrypting object...");
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            return new SealedObject(object, cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException | IOException | IllegalBlockSizeException e) {
            logger.error("Error encrypting object", e);
            throw new RuntimeException("Error encrypting object", e);
        }
    }

    // Decrypt a serializable object using the specified algorithm, key, and IV
    public static Serializable decryptObject(String algorithm, SealedObject sealedObject,
                                             SecretKey key, IvParameterSpec iv) {
        try {
            logger.info("Decrypting object...");
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            return (Serializable) sealedObject.getObject(cipher);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException |
                 InvalidKeyException | ClassNotFoundException | BadPaddingException |
                 IllegalBlockSizeException | IOException e) {
            logger.error("Error decrypting object", e);
            throw new RuntimeException("Error decrypting object", e);
        }

    }
}
