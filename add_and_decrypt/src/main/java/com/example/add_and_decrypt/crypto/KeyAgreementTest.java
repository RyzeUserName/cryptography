package com.example.add_and_decrypt.crypto;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.security.*;

/**
 * KeyAgreement  测试
 * @author Ryze
 * @date 2019-09-24 10:39
 */
public class KeyAgreementTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        //假如 密钥交换的是两方 那么
        KeyPairGenerator instance = KeyPairGenerator.getInstance("DH");
        //两方的交换的密钥
        KeyPair keyPair1 = instance.genKeyPair();
        KeyPair keyPair2 = instance.genKeyPair();
        //实例化
        KeyAgreement agreement1 = KeyAgreement.getInstance("DH");
        agreement1.init(keyPair1.getPrivate());
        agreement1.doPhase(keyPair2.getPublic(), true);
        //生成
        SecretKey des1 = agreement1.generateSecret("DES");
        byte[] bytes = agreement1.generateSecret();
        //实例化
        KeyAgreement agreement2 = KeyAgreement.getInstance("DH");
        agreement2.init(keyPair2.getPrivate());
        agreement2.doPhase(keyPair1.getPublic(), true);
        //生成
        SecretKey des2 = agreement2.generateSecret("DES");
        System.out.println(des1.equals(des2));
    }
}
