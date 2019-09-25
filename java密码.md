# JAVA加密

## 1.背景介绍

​	随着社会发展，安全问题日益凸显，存储安全、通信安全、B2C/B2B交易安全、服务交互安全、移动服务安全、内部

​	人为威胁等等，最终会造成企业损失惨重，国际标准组织（ISO）**对计算机安全的定义**：为数据处理建立和采取的技

​	术和管理的安全保护、保护计算机硬件、软件数据不因偶然和恶意的原因而遭到破坏、更改和泄漏。目标是包含： 

​	**保密性**（机密性），**完整性**（防止篡改），**可用性**（可以用），**可靠性**（规定条件下、规定时间内完成规定功能时的

​	稳定性），**抗否认性**（抗抵赖性，不可否认）除此以外，还有**可控性**（安全监控），**可审查性**（确保数据访问者行为

​	有证可查），**认证性**（确认身份真实有效），**访问控制**（授权访问）。

​	

​	OSI安全体系结构，由下到上次序分别是 物理层、数据链路层、网络层、传输层、会话层、表示层、应用层，

​	五类安全服务包括: 认证服务+访问控制服务+数据保密性服务+数据完成性服务+抗否认性

​	![](https://github.com/RyzeUserName/cryptography/blob/master/assets/2019-01-09_173832.png?raw=true)

八类安全机制包括：

**加密机制**，加密算法有对称加密和非对称加密

**数字签名机制**，对应认证服务，用户身份认证和消息认证

**访问控制机制**，对应访问控制服务，对用户权限控制

**数据完整性机制**，避免数据在传输中的干扰，防止篡改，通过单向散列函数计算消息认证码

**认证机制**，认证服务，通常用数字签名认证

**业务流填充机制**，对传输出具加上随机数，确保机密性

**路由控制机制**，对应访问控制机制，选择安全的网路通信路径

**公证机制**，抗否认性，对第三方的行为证明

OSI参开模型为解决网络问题提供了有效的方法，但是卫星和无线网络的出现，使得现有的协议在卫星和无线网络互联时

出现了问题，由此产生了TCP/IP 参考模型，TCP/IP十一组网络协议，包括TCP、IP、UDP、RIP、TELNET、FTP、

SMTP、ARP、TFTP等协议，从上到下分为网络接口层、网络层、传输层和应用层

​	![](https://github.com/RyzeUserName/cryptography/blob/master/assets/2019-01-10_181219.png?raw=true)

网络接口层:通常指链路层安全，可以通过加密方式保证安全，通常依靠物理层（**硬件**）加密

网络层安全：负责数据包的路由选择，负责确保数据包顺利到目的地，一般通过路由**硬件**提高安全

传输层安全：TCP或UDP两种服务，可以通过SSL/TLS加密，而WAP安全得重视，WTLS协议

应用层安全：负责与应用交互，也可通过SSL/TLS加密，WTLS加密



历史：手工加密  -->  机械加密

**科克霍夫原则**：对数据的 安全基于密钥而不是算法的保密

分类：按**时间划分** ：**古典密码学**(以字符为基本加密单元) 

​				位移密码，替代密码，单表替代密码，同音替代密码，多表替代密码，多字母替代密码

​				**现代密码学**(以信息块为基本加密单元)

​	按**加密内容算法**划分：**受限算法**（算法的保密性基于保持算法密码）

​					**基于密钥算法**（算法的保密性基于对密钥的保密）

​	按**密码体制**划分： **对称密码体制**(单密钥体制或者私钥密钥体制，加密与解密的密钥一致)

​					常见的算法 DES,AES，常用的技巧**替代和移位**

​				     **非对称密码体制**（双钥密码体制或者公钥密码体制，加密用公钥，公开的，解密用私钥，保密的）

​					常见的算法 RSA

​	按**明文处理方法**划分: **分组密码**（加密时将明文分成固定长度的分组，用同一密钥和算法对每一块加密，输出也是固

​					   定长度的密文），分组密码多应用于网络加密，

​					工作模式：ECB（电子密码本模式，块与块之间没关系，相同的明文生成相同的密文）

​							CBC（密文链接模式，明文 XOR 前一密文 在加密，目前已经不安全）

​							CFB（密文反馈模式，类似于自同步流密码，前一密文加密 XOR 明文 =密文）

​							OFB （输出反馈模式，前一密钥 加密  XOR 明文 =密文）

​							CTR（计数器模式，计数器+1 加密 XOR 明文=密文）

​					  **流密码** （又称序列密码，指加密时每次加密一位或 一个字节的明文，对系统资源要求极低）

​					常见算法 RC4，SEAL常用于手机端，生成的密文与明文长度一致，分为同步流密码（类似于

​					CTR，每块加密的密钥可以同时生成，同步进行加密和解密）+自同步流密码（前一步的密钥/密

​					文作为下一步加密的密钥）

​					

## 2.java加密

​	java安全领域，分为4部分，

​	JCA（java加密体系） 证书，数字签名，消息摘要，密钥对生成器

​	JCE（java加密扩展包） 在JCA基础上 提供各种加密算法 DES AES RSA等

​	JSSE（java 安全套接字扩展包） 提供基于ssl的加密功能

​	JAAS（java 鉴别与安全服务）用户身份鉴别，通过可配置的方式集成与各个系统中

​	注意：JCA和JCE是java平台提供的用安全和加密服务的两组API，并不执行任何算法，只是接口，用于连接应用和

​	实际算法，美国对于JCA可以出口，JCE限制出口，软件开发商根据JCE接口（安全提供接口）将各种算法实现后，

​	打包成一个Provider（安全提供者），动态加载到java 环境，安全提供者是安全算法提供者，sun提供了如何开发安

​	全提供者的细节，Bouncy，Castle提供了可以在J2ME/J2EE/J2SE平台得到支持的API，并且是免费的

​	安全算法提供者实现了两个抽象概念：引擎（操作 加密 解密）和算法（如何执行）

​	jdk中

![1569204771381](https://github.com/RyzeUserName/cryptography/blob/master/assets/1569204771381.png?raw=true)

### 1.java.security包

#### 	1.Provider类（提供者）

​	 This class represents a "provider" for the Java Security API, where a provider implements some or all parts of Java Security. Services that a provider may implement include:

​	Algorithms (such as DSA, RSA, MD5 or SHA-1).

​	Key generation, conversion, and management facilities (such as for  algorithm-specific keys).

​	实现类：

​	![1569207396328](https://github.com/RyzeUserName/cryptography/blob/master/assets/1569207396328.png?raw=true)

​	jdk中的提供者在

​	![1569208175390](https://github.com/RyzeUserName/cryptography/blob/master/assets/1569208175390.png?raw=true)

​	很显然需要第三方的软件的话，需要在这配置

#### 	2.Security类

​	This class centralizes（集中） all security properties and common security  methods. One of its primary uses is to manage providers.

​	The default values of security properties are read from an implementation-specific location, which is typically the properties file  {@code lib/security/java.security} in the Java installation directory.

​	final 的类，读取 lib/security/java.security 文件中的配置

​	查看当前环境中管理的类

​	![1569209114225](https://github.com/RyzeUserName/cryptography/blob/master/assets/1569209114225.png?raw=true)

#### 3.MessageDigest类

​	MessageDigest 实现了消息摘要算法

​	我的jdk1.8版本 支持   MD5  SHA-1  SHA-256 算法

```java
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
```

#### 4.DigestInputStream类	

消息摘要输入流，继承 FilterInputStream

```java
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        byte[] bytes = "sha".getBytes();
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        DigestInputStream digestInputStream = new DigestInputStream(new ByteArrayInputStream(bytes), md5);
        //读    一定需要读
        digestInputStream.read(bytes, 0, bytes.length);
        byte[] digest = digestInputStream.getMessageDigest().digest();
        //关流
        digestInputStream.close();
        printC(digest);
    }
    public static void printC(byte[] bytes){
        for (byte b:bytes) {
            System.out.print(b);
        }
        System.out.println();
    }
```

#### 5.DigestOutputStream类

继承FilterOutputStream ，与上面的类对应，是通过write，消息摘要输出流

```java
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        byte[] bytes = "sha".getBytes();
        MessageDigest md5 = MessageDigest.getInstance("md5");
        DigestOutputStream digestOutputStream = new DigestOutputStream(new ByteArrayOutputStream(), md5);
        //写
        digestOutputStream.write(bytes);
        byte[] digest = digestOutputStream.getMessageDigest().digest();
        //关流
        digestOutputStream.close();
        printC(digest);
    }
	public static void printC(byte[] bytes){
        for (byte b:bytes) {
            System.out.print(b);
        }
        System.out.println();
    }
```

#### 6.key接口

​	是所有密钥接口的顶层接口

​	所有秘钥特征：1. 算法  

​							 2.编码 (密钥的外部编码形式 《密钥展示编码》)  返回xx编码格式的密钥

​							3.格式  返回密钥的编码格式

​	SecretKey，PublicKey，PrivateKey 接口均继承Key接口 密钥体系

#### 7.AlgorithmParameters类

提供参数的不透明表示  不可直接get到，而是得参数相关联的算法名以及该参数集的某类编码

支持 AES DES DESede DiffieHellman  DSA 等

```java
 public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        //指定算法  算法跟参数有关
        AlgorithmParameters des = AlgorithmParameters.getInstance("DES");
        //添加参数
        des.init(new BigInteger("19050619766489163472469").toByteArray());
        //获取参数字节数组
        byte[] encoded = des.getEncoded();
        System.out.println(new BigInteger(encoded).toString());
    }
```

#### 8.AlgorithmParameterGenerator 类

用于生成某种算法的参数集合

目前   支持 DiffieHellman   DSA

```java
 public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        AlgorithmParameterGenerator dsa = AlgorithmParameterGenerator.getInstance("DSA");
        dsa.init(512);
        AlgorithmParameters algorithmParameters = dsa.generateParameters();
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(encoded).toString());
    }
```

注意：AlgorithmParameters AlgorithmParameterGenerator  很少用到，除非对算法参数要求极为严格

#### 9.KeyPair 类

钥匙串，公、私钥

#### 10.KeyPairGenerator

​	KeyPair 生成器

​	目前支持   DiffieHellman (1024)  DSA 1024 RSA (1024, 2048)

```java
    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        //初始化
        ras.initialize(512);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
    }
```

#### 11.KeyFactory

密钥工厂，用于生成公/私钥，还可以通过密钥规范还原密钥

目前支持 DiffieHellman  DSA  RSA

```java
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
```

#### 12.SecureRandom

安全随机数生成器，继承 Random ，起到强化加强随机数生成器的作用，一般用于配合密钥生成

```java
 public static void main(String[] args) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        //初始化
        rsa.initialize(512,secureRandom);
        KeyPair keyPair = rsa.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
    }
```

#### 13.Signature

数字签名

支持 SHA1withDSA  SHA1withRSA    SHA256withRSA

```java
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
```



#### 14.SignedObject

用于表示一个运行时不会发生变化的签名对象（其实就是 内置一个 object 是源对象的深层复制）

支持 SHA256withDSA   SHA256withRSA 等

```java
public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        //数据
        byte[] datas = "data".getBytes();

        //生成公私钥
        KeyPairGenerator ras = KeyPairGenerator.getInstance("RSA");
        ras.initialize(512);
        KeyPair keyPair = ras.generateKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();

        //签名
        Signature sha256withRSA = Signature.getInstance("SHA256withRSA");
        SignedObject signedObject = new SignedObject(datas, aPrivate, sha256withRSA);
        byte[] signature = signedObject.getSignature();
        //校验签名
    	sha256withRSA.update(signature);
        boolean verify = signedObject.verify(aPublic, sha256withRSA);
        System.out.println(verify);

    }
```

#### 15.Timestamp

数字时间戳，用于封装时间戳的信息，并且是不可变的

```java
public static void main(String[] args) throws CertificateException, FileNotFoundException {
        //证书 生成
        CertificateFactory x509 = CertificateFactory.getInstance("X509");
        FileInputStream fileInputStream = new FileInputStream("D:\\x.cer");
        CertPath certificate = x509.generateCertPath(fileInputStream);
        //生成
        Timestamp timestamp = new Timestamp(new Date(), certificate);
    }
```

证书 生成需要参考后面

#### 16.CodeSigner

封装了代码签名者信息，且不可变，代码签名

```java
public static void main(String[] args) throws CertificateException, FileNotFoundException {
        //证书 生成
        CertificateFactory x509 = CertificateFactory.getInstance("X509");
        FileInputStream fileInputStream = new FileInputStream("D:\\x.cer");
        CertPath certificate = x509.generateCertPath(fileInputStream);
        //生成 timestamp
        Timestamp timestamp = new Timestamp(new Date(), certificate);
        //实例化
        CodeSigner codeSigner = new CodeSigner(certificate, timestamp);
        //比较
        codeSigner.equals(new CodeSigner(certificate, timestamp));
    }
```



#### 17. KeyStore

密钥库，用于管理密钥和证书的存储。提供了相当完善的接口来访问和修改密钥仓库中的信息

目前支持 PKCS12 、jks 等 

```java
    public static void main(String[] args) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        //获取实例
        KeyStore instance = KeyStore.getInstance(KeyStore.getDefaultType());
        KeyStore.PasswordProtection passwordProtection = new KeyStore.PasswordProtection("password".toCharArray());
        //获取私钥
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) instance.getEntry("别名", passwordProtection);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
    }
```



### 2.javax.crypto 包

加密操作提供类和接口，加密的 Cipher类

#### 1.Mac类

​	消息摘要的一种，不同于MessageDigest，需要秘钥才可以生成摘要，即安全消息摘要

​	基于加密散列函数的MAC机制被称为HMAC。 HMAC可以与任何加密散列函数一起使用，例如MD5或SHA-1与秘密共	享密钥的组合

​	支持 HmacMD5   HmacSHA1   HmacSHA256 

```java
public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = "Mac".getBytes();
        //获取密钥
        KeyGenerator hmacMD51 = KeyGenerator.getInstance("HmacMD5");
        SecretKey secretKey = hmacMD51.generateKey();
        //获取实例
        Mac hmacMD5 = Mac.getInstance("HmacMD5");
        //初始化
        hmacMD5.init(secretKey);
        //签名
        byte[] bytes = hmacMD5.doFinal(data);
    }
```



#### 2.KeyGenerator 类

提供了一个秘密（对称）密钥生成器的功能  KeyGenerator对象是可重用的，即在生成一个密钥之后，可以重新使用相同的KeyGenerator对象来生成其他密钥。 

支持： AES （128）  DES （56） DESede （168） HmacSHA1 HmacSHA256  等

```java
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //获取密钥
        KeyGenerator hmacMD51 = KeyGenerator.getInstance("HmacMD5");
        SecretKey secretKey = hmacMD51.generateKey();
    }
```



#### 3.KeyAgreement类

提供了密钥协议（或密钥交换）协议的功能。DiffieHellman 实现中使用它

```java
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
```

以上代码没有执行成功！提示没有该算法，也不知道怎么搞



#### 4.SecretKeyFactory类

用于产生密钥 的工厂，类似于KeyFactory

```java
  public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        //des 的key
        KeyGenerator des = KeyGenerator.getInstance("DES");
        SecretKey secretKey = des.generateKey();
        byte[] encoded = secretKey.getEncoded();
        //获取规范
        DESKeySpec desKeySpec = new DESKeySpec(encoded);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        //生成key
        SecretKey secretKey1 = secretKeyFactory.generateSecret(desKeySpec);
        //比较 发现是一样的
        System.out.println(secretKey.equals(secretKey1));
    }
```



#### 5.Cipher类

为加密解密提供密码功能。jce的核心

Cipher类 实例化 getInstance()  参数  “算法/模式/填充” 或   “算法”  的字符串 

支持 

AES/CBC/NoPadding （128） 
AES/CBC/PKCS5Padding （128） 
AES/ECB/NoPadding （128） 
AES/ECB/PKCS5Padding （128） 
DES/CBC/NoPadding （56） 
DES/CBC/PKCS5Padding（56） 
DES/ECB/NoPadding（56） 
DES/ECB/PKCS5Padding （56） 
DESede/CBC/NoPadding （168） 
DESede/CBC/PKCS5Padding （168） 
DESede/ECB/NoPadding （168） 
DESede/ECB/PKCS5Padding （168） 
RSA/ECB/PKCS1Padding （ 1024，2048 ） 
RSA/ECB/OAEPWithSHA-1AndMGF1Padding （ 1024，2048 ） 
RSA/ECB/OAEPWithSHA-256AndMGF1Padding （ 1024，2048 ） 

```java
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //包装key
        cipher.init(Cipher.WRAP_MODE, secretKey);
        //keys 传递过去 应该
        byte[] keys = cipher.wrap(secretKey);

        //解包装
        cipher.init(Cipher.UNWRAP_MODE, secretKey);
        Key des = cipher.unwrap(keys, "DES", Cipher.SECRET_KEY);
        //两个是一样的
        System.out.println(des.equals(secretKey));

        //加密
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] bytes = cipher.doFinal("data".getBytes());

        //解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] doFinal = cipher.doFinal(bytes);
        System.out.println(new String(doFinal));
    }
```



#### 6.CipherInputStream类

密钥输入流，从流中直接解密

```java
public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //解密模式
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //初始化流
        CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(new File("secret")), cipher);
        DataInputStream dataInputStream = new DataInputStream(cipherInputStream);
        //读出解密的数据
        String s = dataInputStream.readUTF();
        dataInputStream.close();
        cipherInputStream.close();
    }
```

#### 7. CipherOutputStream类

密钥输出流，写入加密的数据

```java
 public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        //des 生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化
        Cipher cipher = Cipher.getInstance("DES");
        //加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //初始化流
        CipherOutputStream cipherInputStream = new CipherOutputStream(new FileOutputStream(new File("secret")), cipher);
        DataOutputStream dataInputStream = new DataOutputStream(cipherInputStream);
        //写入加密的数据
        dataInputStream.writeUTF("data");
        dataInputStream.close();
        cipherInputStream.close();
    }
```

#### 8.SealedObject类

该类使程序员能够使用加密算法创建对象并保护其机密性

SealedObject 里有个深度拷贝的原对象

```java
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
```



### 3.java.security.spec 包 与javax.crypto.spec 包

秘钥规范和算法参数规范的类和接口

#### 1.KeySpec 与 AlgorithmParameterSpec 接口

将所有参数规范分组，为其提供安全类型

**KeySpec** 

加密密钥的密钥材料的规范 

如果密钥存储在硬件设备上，则其规范可能包含有助于识别设备上的密钥的信息。

**AlgorithmParameterSpec** 

密码参数的（透明）规范。

此接口不包含方法或常量。 其唯一目的是为所有参数规格分组（并提供类型安全性）。  所有参数规范必须实现此接口。 

#### 2.EncodedKeySpec 类

该类表示编码格式的公钥或私钥。 

子类 PKCS8EncodedKeySpec （私钥）， X509EncodedKeySpec （公钥）



#### 3.SecretKeySpec类

#### 4.DESKeySpec类

### 4.java.security.cert包

证书解析、管理、撤销、证书路径的类和接口

#### 1.Certificate类

#### 2.CertificateFactory类

#### 3. X509Certificate类

#### 4.CRL类

#### 5.X509CRLEntry类

#### 6.X509CRL类

#### 7.CertPath类

### 5.javax.net.ssl包

用于安全套接字

#### 1.KeyManagerFactory类

#### 2.TrustManagerFactory类

#### 3.SSLContext类

#### 4.HttpsURLConnection类

#### 5.SSLSession接口

#### 6.SSLSocketFactory类

#### 7.SSLSocket类

#### 8.SSLServerSocketFactory类

#### 9.SSLServerSocket类