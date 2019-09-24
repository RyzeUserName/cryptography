package com.example.add_and_decrypt.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Mac 测试
 * @author Ryze
 * @date 2019-09-24 10:00
 */
public class MacTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = "Mac".getBytes();
        //获取密钥
        KeyGenerator hmacMD51 = KeyGenerator.getInstance("HmacMD5");
        SecretKey secretKey = hmacMD51.generateKey();
        //获取实例
        Mac hmacMD5 = Mac.getInstance("HmacMD5");
        //初始化
        hmacMD5.init(secretKey);
        //签名
        byte[] bytes = hmacMD5.doFinal(data);
    }
}
