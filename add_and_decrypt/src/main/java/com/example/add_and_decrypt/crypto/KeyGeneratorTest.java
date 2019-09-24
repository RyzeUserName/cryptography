package com.example.add_and_decrypt.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * KeyGenerator 测试
 * @author Ryze
 * @date 2019-09-24 10:34
 */
public class KeyGeneratorTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //获取密钥
        KeyGenerator hmacMD51 = KeyGenerator.getInstance("HmacMD5");
        SecretKey secretKey = hmacMD51.generateKey();
    }
}
