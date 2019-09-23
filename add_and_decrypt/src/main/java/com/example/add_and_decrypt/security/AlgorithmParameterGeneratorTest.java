package com.example.add_and_decrypt.security;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;

/**
 * AlgorithmParameterGenerator 测试
 * @author Ryze
 * @date 2019-09-23 15:48
 */
public class AlgorithmParameterGeneratorTest {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        AlgorithmParameterGenerator dsa = AlgorithmParameterGenerator.getInstance("DSA");
        dsa.init(512);
        AlgorithmParameters algorithmParameters = dsa.generateParameters();
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(encoded).toString());
    }
}
