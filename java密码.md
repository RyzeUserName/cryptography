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

​	2.Security类

​	This class centralizes（集中） all security properties and common security  methods. One of its primary uses is to manage providers.

​	The default values of security properties are read from an implementation-specific location, which is typically the properties file  {@code lib/security/java.security} in the Java installation directory.

​	final 的类，读取 lib/security/java.security 文件中的配置

​	查看当前环境的类

​	![1569209114225](https://github.com/RyzeUserName/cryptography/blob/master/assets/1569209114225.png?raw=true)

​	

### 2.javax.crypto 包

### 3.java.security.spec 包 与javax.crypto.spec 包

### 4.java.security.cert包

### 5.javax.net.ssl包