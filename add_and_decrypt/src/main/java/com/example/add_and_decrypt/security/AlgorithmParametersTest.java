package com.example.add_and_decrypt.security;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;

/**
 * AlgorithmParameters 测试
 * @author Ryze
 * @date 2019-09-23 15:07
 */
public class AlgorithmParametersTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        //指定算法  算法跟参数有关
        AlgorithmParameters des = AlgorithmParameters.getInstance("DES");
        //添加参数
        des.init(new BigInteger("19050619766489163472469").toByteArray());
        //获取参数字节数组
        byte[] encoded = des.getEncoded();
        System.out.println(new BigInteger(encoded).toString());
    }
}
