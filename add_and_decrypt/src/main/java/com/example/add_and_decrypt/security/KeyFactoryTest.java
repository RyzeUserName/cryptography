package com.example.add_and_decrypt.security;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * KeyFactory 测试
 * @author Ryze
 * @date 2019-09-23 17:00
 */
public class KeyFactoryTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //密钥生成
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        //初始化
        ras.initialize(1024);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        byte[] encoded = aPrivate.getEncoded();
        //根据 私钥字节  获取密钥规范
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(encoded);
        //工厂还原密钥
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = rsa.generatePrivate(pkcs8EncodedKeySpec);
        System.out.println(privateKey.equals(aPrivate));
    }
}
