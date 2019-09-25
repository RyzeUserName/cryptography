package com.example.add_and_decrypt.crypto;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Cipher 测试
 * @author Ryze
 * @date 2019-09-24 17:48
 */
public class CipherTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //包装key
        cipher.init(Cipher.WRAP_MODE, secretKey);
        //keys 传递过去 应该
        byte[] keys = cipher.wrap(secretKey);

        //解包装
        cipher.init(Cipher.UNWRAP_MODE, secretKey);
        Key des = cipher.unwrap(keys, "DES", Cipher.SECRET_KEY);
        //两个是一样的
        System.out.println(des.equals(secretKey));

        //加密
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] bytes = cipher.doFinal("data".getBytes());

        //解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] doFinal = cipher.doFinal(bytes);
        System.out.println(new String(doFinal));
    }
}
