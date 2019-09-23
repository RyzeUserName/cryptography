package com.example.add_and_decrypt.security;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

/**
 *  security 测试
 * @author Ryze
 * @date 2019-09-23 11:20
 */
public class SecurityTest {
    public static void main(String[] args) {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println(provider);
            for (Map.Entry<Object, Object> entry : provider.entrySet()) {
                System.out.println(entry.getKey());
            }
            System.out.println("---------------------");
        }

    }
}
