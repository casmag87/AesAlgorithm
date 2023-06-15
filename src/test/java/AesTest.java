import com.sun.javaws.security.Resource;
import util.AesUtil;
import org.junit.jupiter.api.Assertions;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class AesTest {

    @Test
    void givenString_whenEncrypt_thenSuccess()
            throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        String input = "123456";
        SecretKey key = AesUtil.generateKey(128);

        IvParameterSpec ivParameterSpec = AesUtil.generateIv();
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipherText = AesUtil.encrypt(algorithm, input, key, ivParameterSpec);
        String plainText = AesUtil.decrypt(algorithm, cipherText, key, ivParameterSpec);


        Assertions.assertEquals(input, plainText);
    }




}
