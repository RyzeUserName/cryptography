package com.example.add_and_decrypt.security;

import java.security.*;

/**
 * KeyStore 测试
 * @author Ryze
 * @date 2019-09-23 19:17
 */
public class KeyStoreTest {
    public static void main(String[] args) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        //获取实例
        KeyStore instance = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("password".toCharArray());
        //获取私钥
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) instance.getEntry("别名", passwordProtection);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    }
}
