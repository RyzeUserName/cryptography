package com.example.add_and_decrypt.crypto;

import javax.crypto.*;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * SealedObject 测试
 * @author Ryze
 * @date 2019-09-25 17:01
 */
public class SealedObjectTest {
    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        String data="1223444";
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //加密
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        //初始化
        SealedObject sealedObject = new SealedObject(data, cipher);

        //初始化
        Cipher cipher1 = Cipher.getInstance("DES");
        cipher1.init(Cipher.DECRYPT_MODE,secretKey);
        //获取对象
        Object object = sealedObject.getObject(cipher1);
        System.out.println(object.equals(data));
        //获取对象
        Object object1 = sealedObject.getObject(secretKey);
        System.out.println(object.equals(object1));
    }
}
