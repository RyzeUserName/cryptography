package com.example.add_and_decrypt.cert;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/**
 * CRL 测试
 * @author Ryze
 * @date 2019-09-26 11:35
 */
public class CRLTest {
    public static void main(String[] args) throws IOException, CertificateException, CRLException {
        //加载证书
        CertificateFactory instance = CertificateFactory.getInstance("X.509");
        FileInputStream stream = new FileInputStream("D:\\x.keystore");
        //获取撤销证书列表
        CRL crl = instance.generateCRL(stream);
        stream.close();
    }
}
