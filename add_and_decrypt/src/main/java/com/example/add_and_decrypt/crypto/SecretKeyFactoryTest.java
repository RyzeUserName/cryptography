package com.example.add_and_decrypt.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * SecretKeyFactory 测试
 * @author Ryze
 * @date 2019-09-24 14:50
 */
public class SecretKeyFactoryTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        //des 的key
        KeyGenerator des = KeyGenerator.getInstance("DES");
        SecretKey secretKey = des.generateKey();
        byte[] encoded = secretKey.getEncoded();
        //获取规范
        DESKeySpec desKeySpec = new DESKeySpec(encoded);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        //生成key
        SecretKey secretKey1 = secretKeyFactory.generateSecret(desKeySpec);
        //比较 发现是一样的
        System.out.println(secretKey.equals(secretKey1));
    }
}
