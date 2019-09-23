package com.example.add_and_decrypt.security;

import java.security.*;

/**
 * Signature 测试
 * @author Ryze
 * @date 2019-09-23 17:18
 */
public class SignatureTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //数据
        byte[] datas = "data".getBytes();

        //生成公私钥
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        ras.initialize(512);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        //签名
        Signature signature = Signature.getInstance("SHA256withRSA");
        //初始化
        signature.initSign(aPrivate);
        signature.update(datas);
        //获取签名
        byte[] sign = signature.sign();

        //校验签名
        signature.initVerify(aPublic);
        //初始化
        signature.update(datas);
        boolean verify = signature.verify(sign);
        System.out.println(verify);
    }
}
