package com.example.add_and_decrypt.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MessageDigest 测试
 * @author Ryze
 * @date 2019-09-23 11:39
 */
public class MessageDigestTest {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] bytes = "sha".getBytes();
        MessageDigest sha_256 = MessageDigest.getInstance("SHA-256");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        //摘要
        byte[] shaDigest = sha_256.digest(bytes);
        byte[] md5Digest = md5.digest(bytes);
        printC(shaDigest);
        printC(md5Digest);
    }
    public static void printC(byte[] bytes){
        for (byte b:bytes) {
            System.out.print(b);
        }
        System.out.println();
    }
}
