# cryptography

# 密码技术

## 1.介绍

​	![](https://github.com/RyzeUserName/cryptography/tree/master/assets/d6d9992a221d6abb35df1acc2105b32.png)

​	**常识**：

​		1.不要使用保密算法  （密码算法早晚会公诸于世    高强度的加密算法很难实现）

​		2.使用低强度的密码比不加密更加危险 （信息被加密 并不代表安全感。与其使用低强度密码 还不如不加密）

​		3.任何密码总有一天会被破解 （时间问题而已 ，一次性密码本（不是现实可用的算法），量子算法（之后））

​		4.密码只是信息安全的一部分 （社会工程攻击 去获取你的秘钥等）

​		**注意**：密码隐藏的是消息内容，而隐写术隐藏的是消息本身

## 2.例子

### 1.凯撒密码

​		类似于英文字母的平移n位，n即为密匙  abc 平移三位 DEF 

​		可以用暴力破解（搜索穷举）

### 2.简单替换

​		将26个英文字母 每个字母按照简单替换密码的对应表（密钥）进行替换

​		并不能用暴力破解因为密钥空间太大，花费时间太长，可以用频率分析（统计学）破解

​		頻率分析：高频字母和低频字母均可以成为线索（突破口），密文越长越容易破解，		

### 3.Enigma

​		根据每日密钥设置 Enigma，然后加密 通信密码（密码一般两遍表示通信无误） ，根据通信密码设置Enigma ，

​		再然后加密信息，将加密密码和加密信息发送 解密一样

​		**注意：**密码算法中可变的部分是密钥，密码算法为可重复使用的部分（增加被破解风险）

## 3.对称加密（共享密钥密码）

### 1.比特序列运算

计算机序列编码，0和1组成

### 2.XOR运算

异或运算，只要不相同，那么就是1否则是0

A XOR B  XOR B = A

### 3.一次性密码本

​	明文 XOR  随机密钥 = 密文  解密  密文 XOR 随机密钥 = 结果

​	无法破译的，暴力破解 即便 拥有超强的计算能力和足够的时间，关键是也无法确定到底哪个正确，所以无法破译

​	存在的问题：	1.密钥配送  （无法安全配送，要是能安全配送那直接送明文不更好？）

​				2.密钥保存  （无法安全保存，要是能安全保存那直接送明文不更好？）

​				3.密钥的重用 （不存在，一次性密码本，一次性使用）

​				4.密钥的同步 （与明文一样长，那直接同步明文）

​				5.密钥的生成 （无重复性的随机数）

​	综上：一次性密码本是一种几乎没有实用性的密码（流密码就是借鉴这个理论）

### 4.DES

​	使用了Feistel网络。

​	对称加密，密钥64比特，每隔7比特设置一个用于检查错误的比特，DES 每次加密只能对64比特，所以分组加密

​	每64 比特 加密16轮 ，一轮是 64比特分成 32+32 ，先根据右侧32位+轮函数+ 局部密钥 生成的结果 XOR 左侧  生成

​	加密的左侧，加密的左侧+原来的右侧 进行下轮加密 （下轮会 根据左侧加密右侧，之后也是 左右左右...）

​	缺点：没有考虑差分析和线性分析，容易被破解（选择明文攻击）也就可以暴力破解

### 5.三重DES

​	对DES加强，将DES重复三次所得到的密码算法，使用三个密钥加密。解密密钥的使用顺序与加密正好相反

### 6.AES（Rijndael）

​	分组长度128比特（16字节），密钥长度128,192和256 三种

​	使用SPN结构，16字节长度明文  4*4 矩阵 ， SubBytes（简单替换）+ShiftRow（横平移，每横平移位不同）+

​	MixColumns（对每列进行 XOR运算）+AddRoundKey（对每个字节运算）此为一轮，加密需要重复10·14轮，

​	解密正好相反的顺序

## 4.分组密码的模式

只对固定长度的明文进行加密，超出的部分需要迭代处理，迭代的方法就是**模式**，分组密码处理完一个分组就结束了，不需要通过内部状态记录加密的进度（以上除了一次性密码本都是）。而流密码对数据流进行连续处理的一类密码算法（一次性密码本）。

明文分组：分组密码算法中作为加密对象的明文。

密文分组：使用分组密码算法将明文分组加码之后所生成的密文。

最后一组长度小于分组长度时，会用一些特殊数据填充，都可以被**填充提示攻击** 。

**模式**： 	

### 1.ECB

​		 (电子密码本模式) 直接加密的方式

​		![](.\assets\1546495618(1).jpg)

​		**缺点**：相同明文分组结果是一样的，密文的相同代表明文的相同，无需破译密码就能够操作明文。​		

### 2.CBC

​		（密码分组链接模式）将前一一个密文分组与当前明文分组内容混合起来进行加密(XOR 需要个初始化向	

​		量IV《必须使用不可预测的随机数》,第一组的加密）

​	![](.\assets\1546495680(1).jpg)

​		**缺点**：有一组的缺失 导致后续的密文 不可解析（可以对初始化向量进行攻击，SSL/TLS 1.0的缺陷）

### 3.CTS 

​			 当明文长度不能被分组长度整除，最后一个分组进行填充，该模式使用最后一个分组的前一密文

​			分组数据进行填充，他通常和ECB模式以及CBC模式配合使用。

​			![](.\assets\1546495860.jpg)

### 4.CFB

​			（密文反馈模式）  前一组密文  加密 XOR  当前组的明文 = 当前组的密文  （第一次是 初始化向量 ）与一

​			次性密码本很像，有密码算法生成的比特序列称为 密匙流，伪随机数生成器，该模式可以看做是使用分组

​			密码来实现流密码的方式，解密依然是加密的算法 前一组密文  加密 XOR  当前组的密文=当前组的明文

​	![](.\assets\1546495910(1).jpg)

​			**缺点**：重放攻击  （将上次密文 重复发送）（无法确定 是通讯错误 还是 被人篡改）

### 5.OFB

​			（输出反馈模式） 	对初始化向量加密 XOR 明文1 =密文 1

​							上面的加密再次加密 XOR 明文2 =密文2 

​							解密也是如此。

​			生成密匙与进行XOR可以并行

​			![](.\assets\2019-01-03_141312.png)

### 6.CTR

​			（计数器模式）通过将逐次累加的计数器进行加密来生成密匙流的流密码，流密码 XOR 明文 =密文

​			计数器分成两部分，前一部分为每次加密固定生成的，后一部分为累加部分，以计数器的方式模仿生成随

​			机序列，CTR可以并行计算，速度非常快。

​		![](.\assets\2019-01-03_141905.png)

​	在CTR 模式上 增加 认证功能 **GCM**模式 ，生成密文的同时生成认证信息，从而判断密文是否合法。

### 7.小结

​	![](.\assets\1546498720(1).jpg)

## 5.公钥密码（非对称密码）

​	对称加密的存在**密钥配送问题**，**密钥必须要发送，但又不能发送**。

​	解决：1.事先共享（数量局限性）

​		2.通过密钥分配中心来解决 （分配中心存在负荷，也是优先攻击的目标）

​		3.通过Diffie-Hellman 密钥交换解决（通信双方可以各自生成相同的密钥）

​		4.通过公钥密码解决（公钥用来加密，只有拥有解密密钥的人才能解密）

​	**介绍**：公钥密码中密钥分为加密密钥和解密密钥，发送者用加密密钥加密，接收者使用解密密钥解密

​		加密密钥是公开的也叫**公钥**，解密密钥是私有的也叫**私钥**，公钥和私钥一一对应，一对公钥和私钥成为**密钥对**

​		处理速度很慢只有对称密码的几百分之一，**注意：密钥密码只解决了密钥配送问题，并不是解决了所有问题**

​		无法解决共要认证问题等。。

### 1.时钟运算

​	假设一个时钟 0到11 	

​	![](.\assets\1546504270(1).jpg)

​	**加法** 向右旋转  在7 位置 向右旋转6格 那么停在  （6+7）mod 12 =1 上

​	**减法** 加法的逆运算类似向左旋转（但时钟不可以向左旋转） 在7位置上旋转多少格子到0 刻度

​	（7+x）mod 12 =0   计算得到 5 或者 -7  也就是说 减法可以转换成加法 （x=余数+12 -7）

​	**乘法**  相当于多次加法， 7*4 =7+7+7+7  相当于向右旋转4个 7刻度 计算与加法相同

​	7*4 mod 12 =1

​	**除法** 乘法的逆运算 7* x mod 12 =1  将0到11 数字带入，发现7是可以的

​		x * y mod 12 =1 在以 12 为模 的世界里，x与y 互为倒数，**实际上某个数是否存在倒数 与公钥算法RSA中一个公**

​		**钥是否存在相对应的私钥 直接相关**。

​		我们将 0 到11 的数 放在x 位置，相当于，旋转几个x 刻度可以将指针转到1 刻度上，经分析1 5 7 11 是可以的，

​		也就是这些数存在倒数，我们再回头看这些数，会发现，这些数字与12 互为质数（与12 的最大公约数是1）

​	**乘方**     7^4 =7 * 7 * 7 * 7   将将将 向右旋转7个刻度 重复7 次 重复7次 重复7次

​		7^4 mod 12 = 7*7 mod 12 *  7 * 7 mod 12= 1*1 =1

​	**对数**  乘方的逆运算，也称为**离散对数**

​		7^x mod 13 =1  那么将 0到 12 带入 8可以成立 （因为 7^ x mod 12=1 0 就可以，增加一下计算，选的13 无任

​		何其他意义），离散对数计算非常困难，能快速计算的算法到现在还未发现，Diffie-Hellman 密钥交换协议以及

​		ElGamal公钥算法中就运用了离散对数

### 2.RSA

​	最广泛的公钥密码算法，由其开发者（三个）名字首字母组成。

​	**加密**：
$$
密文  = 明文^E mod N      (RSA 加密)
$$
​	**E和N 组合就是公钥，写成（E,N）或者{E,N} **

​	**解密**
$$
明文 = 密文^ D mod  N (RSA 解密)
$$
​	**D和N组合就是私钥，写成(D,N)或者{D,N}**

​	![](.\assets\2019-01-03_172302.png)

​	**生成密钥对**：生成N->生成L->生成E->生成D

​		求N，两个较大（太大不好计算，太小容易被破解）的质数p和q ，N=p*q

​		求L，L是 p-1 和q-1的最小公倍数，L=lcm（p-1,q-1）

​		求E，1<E<L,且E和L的最大公约数是1，gcd（E,L）=1

​		求D，1<D<L 且E * D mod L =1

​	![](.\assets\2019-01-03_174329.png)

​	**破解RSA**：

​		1.通过明文，计算难度很大

​		2.暴力破解D，计算难度很大

​		3.通过E和N求D，就是求p和q ，并未有高效的大整数质因分解算法，也是很难

​		4.中间人攻击（截取公钥，发送自己的公钥，用自己私钥解密，篡改信息后用截取的公钥加密发送）

​		**也就诞生了另外一个问题：认证**

​		5.选择密文攻击，可以发送任意密文获取错误提示，当数据达到一定程度可以破解

​		RSA-OAEP改良了加密会加上认证信息。

### 3.其他公钥密码

​	用于一般的加密和数字签名

1.ElGamal

​	RAS利用大数质因分解困难，而ElGamal利用mod N 求离散对数的困难度，缺点：密文变成明文的两倍

2.Rabin

​	Rabin利用mod N 求平方根困难度

3.椭圆曲线密码

​	秘钥长度比RAS短，通过椭圆曲线上特定点进行特殊乘法运算来实现，利用了乘法运算的逆运算非常困难的特性

### 4.总结

​	对称密码和公钥密码的机密性会随着密钥长度而变化，这两种加密也不能根据长度直接对比。对比图如下

![](.\assets\2019-01-03_204712.png)

单位是 比特。

一般来说：公钥密码处理速度慢，只有对称密码的几百分之一，因此并不适合用来对很长的消息进行加密，而我们自己生

成质数组合与别人撞车的可能性为0，随着计算机计算能力的提高，密码也会被破译，这一现象**密码劣化**，但是有技术指

导

![](.\assets\2019-01-03_205506.png)

​	**公钥密码解决了密钥配送的问题，基于数学上的困难保障其机密性，而对称密码通过将明文转换成复杂的形式保证其**

​	**机密性**

## 6.混合密码系统

​	**用对称密码提高速度，用公钥密码保护会话密钥**

### 1.混合密码系统

​	对称密码能够解决明文机密性，但是必须解决密钥配送问题，而公钥密码处理速度慢，难以抵御中间人攻击（认证问

​	题），混合密码可以解决这些劣势（认证还不可以解决）。

​	**混合密码组成机制：**

​		1.随机数伪生成器生成对称密码加密使用的会话密钥

​		2.通过密钥，对称密码进行加密信息

​		3.用公钥密码加密会话密钥

​		4.发送加密信息

​		![](.\assets\2019-01-03_212120.png)

### 2.怎么获得高强度

​	其实：**伪随机生成器+对称密码+公钥密码**，那么每种要素的强度影响着最终密码系统的强度

​	可以将密码组合（对称密码+公钥密码）采用不同的分组密码组合方式，产生不同高强度的密码

## 7.单向散列函数

​	获取消息的“指纹”

### 1.单向散列函数概念

​	如何确认 完整性和一致性，文件1 通过散列函数 计算得 散列值1，文件2 通过散列函数 计算 散列值2， 散列值1与 

​	散列值2 对比就可以确认文件1与文件2 是否一样（确认 一致性和完整性）。**散列函数计算消息输入得到散列值，而**

**​	散列值可以用来检查消息的完整性**。**散列值得长度与消息的长度无关**（SHA-256 计算出来的散列值长度永远是256）

​	**性质：**	1.任意长度消息计算出固定长度的散列值，长度也很短

​			2.可以快速计算出散列值

​			3.消息不通散列值也不同	（不同消息产生相同散列值称为碰撞，难以发现的性质称为**抗碰撞性**）

​			都得具备抗碰撞性，**难以发生碰撞性**	

​			4.具备单向性（无法通过散列值推测出消息）

​	**别名**：**消息摘要函数、哈希函数、杂凑函数**

​		输入**消息**也称为 **原像**

​		单向散列函数输出的**散列值**也称为**消息摘要**、**指纹**

​		**完整性**也称为**一致性**

### 2.单向单列函数应用

​		**1.检测软件是否篡改**

​	![](.\assets\2019-01-03_222925.png)

​		**2.基于口令加密**

​		PBE原理是将口令和盐（随机数）混合后计算其散列值，将该散列值作为加密的密钥。

​		**3.消息认证码**

​		消息认证码是将 发送者和接收者之间共享的密钥 和消息 进行混合计算出的散列值，可以用来检测并防止通信过

​		程中的错误、篡改、伪装。

​		**4.数字签名**

​		现实社会的签字盖章在数字世界的实现，数字签名处理非常耗时，一般不会对消息直接进行数字签名，而是对

​		消息计算出散列值，在对散列值进行数字签名。

​		**5.伪随机数生成器**

​		随机数需要具备，事实上不可能根据过去的随机数预测未来的随机数这样的性质，为了保证不可预测性，所以

​		用单行散列函数单向性实现

​		**6.一次性口令**

​		一次性口令，可用单向散列函数构造，经常用于服务器对客户端的合法性认证，保证口令只在通信链路上传一

​		次，因此窃听了也没用。

### 3.单向散列函数例子

​		1.MD4、MD5 产生128 比特（目前已经不安全 强碰撞性 已经不具备 ）

​		2.SHA-1、SHA-256、SHA-384、SHA-512

​		SHA-1产生 160比特散列值	（强碰撞性 已经不具备）

​		SHA-256、SHA-384、SHA-512 统称为SHA-2 产生的散列长度为对应数字（目前尚未被攻破）

![](.\assets\2019-01-03_225803.png)

​		3.PIPEMD-160

​		PIPEMD 已经被攻破，但是 PIPEMD-160还尚未被攻破，比特币用的就是这个

​		4.SHA-3

​		SHA-3是标准，其 具体实现 是 Keccak 算法

​		优点：![](.\assets\2019-01-03_230256.png)

### 4.Keccak

​		是SHA-3标准的单向散列函数算法。可以生成任意长度的散列值，但是为了SHA-3标准 224、256、384、512四

​		个版本,但是SHA-3却没有规定，Keccak有两个函数（SHAKE128 SHAKE256）可以输出任意长度的散列值.

​		Keccak作者在GitHub 上 KeccakTools 工具

​		**1.海绵结构**:将输入的消息吸收到内部状态（吸收阶段），然后再根据内部状态挤出（挤出阶段）响应散列。

![](.\assets\2019-01-03_233647.png)

​	**吸收阶段**：

​		消息切分 r个为单位，将内部状态的r个比特 XOR 分组1 生成 f 函数输入，f函数输出作为下一组计算的内部状

​		态，反复计算出最后结果。作为挤出的输入。

​		f函数将输入数据进行复杂搅拌并输出结果，输入输出长度均为b=r+c,内部初始状态为0 ，通过反复操作，将信

​		息一点点吸收到内部状态中

​		r称为比特率

​		c称为容量，防止将输入消息的一些特征泄露出去。

​	**挤出阶段**：

​		将吸收阶段输出，输入到f 函数计算出 输出分组1，将输出值作为f 函数输入 在计算 输出分组2 ，直到输出散列

​		长度达到目标长度，那么就不用计算，直接输出。

**2.双工结构** 海绵结构的变形

​			![](.\assets\2019-01-04_000958.png)

 **改进**：	不需要将消息全部吸收后才能开始计算。通过双工结构Keccak 不仅可用于计算散列函数计算，还可以覆盖密码

​		学家工具箱中的其他用途，如伪随机数，流密码，认证加密，消息认证等。

**3.Keccak内部状态**

​		b=r+c 比特，按照 x y  z 三个维度总数是b内部状态整体是state，x->row y->colum z->lane 

​		xz平面plane zy平面slice yz平面sheet

**4.函数 f**[b]

​	负责内部状态搅拌的函数f ，参数b称之为宽度 ，可取的值 25 50 100 200 400 800 1600 ,都是25的倍数，SHA-3采用

​	1600，5 * 5 * 64 的内部状态b ，slice面不变是5 * 5 ,b的大小改变 只影响 lane 的大小。（称之为**套娃结构**）		

**5.攻击**

​	Keccak之前的单向散列函数都是通过循环执行压缩函数的方式生成散列值，这种MD结构的，已经出现了理论上可行

​	的有效攻击，但是Keccak 目前并未有 有效攻击

​	**1.暴力破解**，试图破解单向散列函数的**弱抗碰撞性** 攻击 （原像攻击，第二原像攻击）512 比特需要 2的512次

​	**2.生日攻击**，试图破解单向散列函数的**强抗碰撞性** 攻击 （生日悖论）512 比特需要 2的256次

### 5.小结

​	MD5不安全，SHA-1为了兼容，不应该用于新用途，SHA-2、SHA-3 都是安全的。与对称密码一样，**不应该自己研**

​	**制算法**

​	单向散列函数可以实现完整性的检查，无法辨别**伪装**，因此需要**认证**，**消息认证码和数字签名**可以用于认证。

## 8.消息认证码

​	消息被正确传送了吗？可以确认自己收到的消息是否是发送者的本意（是否被篡改，伪装等）即**认证**，消息是否来自

​	正确的发送方。

### 1.介绍

​	**消息认证码是一种确认完整性并进行认证的技术，简称MAC**

​	输入（**任意长度消息**+**共享密钥**） 输出 固定长度的数据 称为**MAC值**

​	**消息认证码是一种与密钥相关联的单向散列函数**

![](.\assets\2019-01-04_105539.png)

​	**当然也存在密钥配送问题。**

### 2.实例

​		1.SWIFT（银行之间的交易）

​		2.IPsec （对 IP 协议增加安全性的一种方式）

​		3.SSL/TLS

### 3.实现

​		1.单向散列函数实现（SHA-2 HMAC）

​		2.分组密码实现（分组密码的密钥作为消息认证码的共享密钥使用）

​		3.其他实现（流密码，公钥密码）

### 4.认证加密

​		同时满足机密性，完整性，人整性三大功能（对称密码+消息认证）

​		1.Encrypt-then-MAC 明文->密文->消息认证码 

​		2.Encrypt-and-MAC  明文->密文+明文->消息认证码

​		3.GCM/GMAC 使用AES分组密码的CTR模式

​		4.HMAC 

![](.\assets\2019-01-04_112225.png)

### 5.攻击

​	1.重放攻击

​		多次发送截获 的信息

​		防御：序号管理，时间戳比对，nonce（事先发送个一次性随机数）

​	2.密钥推测攻击（暴力破解以及生日攻击）

​		利用的就是单向散列函数的单向性和抗碰撞性，密钥应使用密码学安全的、高强度的伪随机数生成器生成，而

​		**不是人为选定**	

​	**注意：** 消息认证不能解决**第三方证明**（向第三方验证 消息的发送方，数字签名解决） 和 **防止否认**（向第三方否认 

​		   消息的发送方，数字签名解决）

## 9.数字签名

### 1.简介

​	消息到底是谁写的，识别篡改和伪装，防止否认

​	各自使用不同的密钥，**签名密钥**生成消息签名，**验证密钥**验证消息签名

​	跟公钥密码很像，但是是反过来使用的(私钥生成签名，公钥验签)。

![](.\assets\2019-01-04_141859.png)

### 2.数字签名的方法

​		1.直接对消息签名的方法

​		2.对消息散列值签名的方法

### 3.疑问

​		1.私钥+明文/明文散列值 为什么具有 签名意义？

​			私钥加密并非为了机密性，而是**只有持有该私钥的人才能生成信息**，这样信息一般称为**认证符号**

​		2.数字签名不能保证机密性？

​			确实不能

​		3.签名可以任意复制，那签名不就没意义？

​			不不，签名只有跟特定的消息绑定在一起才有意义，否则没什么用

​		4.消息内容会不会被修改？

​			那么验签的时候会出错

​		5.数字签名怎么防止否认？

​			防止否认与谁持有密钥有关，消息认证码共享密钥，所以区分不出来谁 发出的消息，而数字签名的生成只

​			有持有密钥的人，其他人只能验签，当然也能说 我的私钥被盗了。。

### 4.实例

​		1.安全信息公告（明文签名）

​		2.软件下载

​		3.公钥证书

​		4.SSL/TLS

### 5.使用RSA实现

$$
签名 = 消息^ D mod  N (RSA 签名/解密)
$$

$$
消息  = 签名^E mod N      (RSA 验签/加密)
$$

### 6.其他实现

​		**1.ElGamal**（1.02版本 签名存在漏洞）

​		**2.DSA** （只用于数字签名）

​		**3.ECDSA** （椭圆密码曲线实现）

​		**4.Rabin**

### 7.攻击

​		1.中间人攻击（替换公钥 解决->公钥证书）

​		2.对单向散列函数攻击

​		3.利用数字签名攻击公钥密码（对散列签名 ，加密和签名采用不同密钥，不要对意思不清楚的消息进行签名）

​		4.潜在伪造（伪造合法签名）（RSA-PASS 加盐 计算散列值，在签名）

​		5.其他攻击（暴力破解找出私钥，尝试RSA的N进行质因分解）

### 8.小结

​		![](.\assets\2019-01-04_151540.png)

​		**密钥是机密性的精华，单向散列函数的散列值是完整性的精华**

​		数字签名 确认消息的完整性，进行认证以及否认防止，但是无法解决的是公钥的正确性（由真正的发送者发

​		送）。为了确认自己得到的公钥是否合法，我们需要使用证书，即为密钥生成数字签名，而验证数字签名又需

​		要另外一个密钥。。。我们需要让公钥和数字签名技术成为一种社会性的基础设施，**公钥基础设施**，PKI

## 10.证书

### 1.简介

​	为了给公钥加上数字签名，**公钥证书**（证书）包含很多信息（公钥。。）由**认证机构**（能生成数字签名的个人或者组

​	织的可信 第三方）施加**数字签名**

​	证书使用情景:![](.\assets\2019-01-04_155447.png)

​	第三步的身份确认有三个级别： 1邮箱 2 第三方数据库 3.当面认证 等级越高 身份确认越严格

### 2.公钥基础设施（PKI）

​		是为了能够有效运用公钥而制定的一系列规范和规格的总称。

​		PKI组成：

​			**用户** 使用KPI的人

​			① 注册公钥的用户

​				生成密钥对（也可以认证机构生成）

​				认证机构注册密钥

​				向认证机构申请证书

​				根据需要申请作废已注册的公钥

​				解密接收到的密文

​				对消息做数字签名

​			②使用已注册公钥的用户

​				将消息加密后发送给接收者

​				验证数字签名

​			**认证机构**  颁发证书的人

​				生成密钥对（也可用户生成）

​				注册公钥时对本人身份进行认证(可以分担给注册机构,但需要认证注册机构)(自己生成的需要注册）

​				生成并颁发证书

​				作废证书  制作证书作废清单CRL

​			**仓库**	保存证书的数据库 也叫证书目录

​		**认证机构对用户的公钥进行了数字签名生成证书，接下来用户需要使用认证机构的公钥 对签名进行认证。而这**

​		**个公钥怎么判断合法？需要其他机构生成一张认证机构的公钥证书，也就是层层证明，最后自证明（自签名）**

​		生成 （从下 到上）与 验证的顺序（从上到下） 正好相反

### 3.对证书攻击

​		1.公钥注册前攻击（身份确认时，并确认指纹）

​		2.注册相似人名攻击 （人类会认错）

​		3.窃取认证机构私钥（一但私钥泄漏，那么生成CRL）

​		4.伪装成认证机构进行攻击

​		5.钻CRL 空子，不及时性，利用时差，攻击

​		6.钻CRL 空子，不及时性，利用时差，否认

## 11.密钥

### 1.介绍

​		**秘密的精华，是个巨大的数字，数字本身的大小并不重要，重要的密钥空间的大小，也就是可能出现密钥的总**

​		**数量，因为密钥空间越大，进行暴力破解就越困难，密钥空间的大小是由秘钥长度决定的。**

​		密钥的价值等价于明文

​		对称密码和公钥密码的密钥是用来**确保机密性的密钥**

​		消息认证和数字签名的密钥是用来**认证的密钥**

​		只用于一次的密钥成为**会话密钥**，一般与**主密钥**结合使用

​		用于**加密密钥的密钥**，混合密码系统中有体现

### 2.管理

​		**1.生成**

​		随机数生成（最好，密码学用途的伪随机数生成器）

​		口令生成(口令 + 盐 -> 散列函数-> 密钥)

​		**2.配送**

​		事先共享，密钥分配中心，公钥密码，Hiffie-Hellman 密钥交换等

​		**3.更新**

​		密钥->单向散列函数->下一个密钥  向后安全，防止破译过去通信内容机制

​		**4.保存**

​			会话级的没必要记住

​			1.放于安全的地方

​			2.密钥加密（额外的KEK 加密）

​		**5.作废**

​			密钥丢失   不需要加密  丢失私钥 等

### 3.Diffie-Hellman 密钥交换

​	也叫Diffie-Hellman 密钥协商，是一种双方仅交换一些公开信息就能够生成密钥的算法，双方通过计算生成一个相同

​	的共享密钥。

​	![](.\assets\2019-01-05_162735.png)

### 4.基于口令的密码	PBE

​	基于口令的密码，java 中的javax.crypto

​	![](.\assets\2019-01-05_165709.png)

解密：1 根据盐 重新生成KEK 2 解密密钥 3 密钥解密消息

​	![](.\assets\2019-01-05_165928.png)

盐 是防止字典攻击。

可以通过 多次单向散列函数拉伸 其安全性

### 5.如何生成安全的口令

​	1.使用只有自己才知道的信息

​	2.将多个不同的口令分开始使用

​	3.有效利用笔记

​	4.理解口令的局限性

​	5.使用口令管理和生成工具

## 12.随机数

### 1.介绍

​	不可预测性的源泉，为了不让攻击者看穿而使用随机数，即不可预测性。

### 2.随机数的性质

​	**随机性**--------不存在统计学偏差，是完全杂乱的数列--------弱伪随机数，**杂乱但不代表不会被看穿**

​	**不可预测性**--------不可能从过去的数列推测出下一个出现的数--------强伪随机数，可以通过**其他的密码技术**实现

​	单向散列函数等

​	**不可重现性**--------除非将数列本身保存下来，否则不能重现相同的数列--------真随机数，**仅靠软件无法**生成不具备不

​	可重复性，因为运行软件的计算机本身具有有限的内部状态，而在状态相同的条件下，软件必然只能生成相同的数，

​	首次出现重复之前的数列的长度称为**周期**，但凡具备周期的数列，都不具备不可重现性，需要从不可重现的现象中

​	获取，比如：周围的温度和声音变化等。。目前利于**热噪声**这一自然现象，已经开发出不可重现随机数列的硬件设备

​	了，例如：英特尔的CPU的RDSEED指令和RDRAND，随机数的原料来自于电路中产生的热噪声，我们称之为真随

​	机数。

​	**以上三个性质，越往下越严格。**

​	![](.\assets\2019-01-07_100315.png)

### 3.伪随机数的生成器

​	随机数可以通过**硬件**来实现，也可以通过**软件**来生成。软件生成的是**伪随机数生成器**，硬件生成的是**随机数生成器。**

​	伪随机数生成器具有“内部状态”，并个人剧外部输入的“种子”来生成伪随机数列。

​	![](.\assets\2019-01-07_170510.png)

​	**伪随机数生成器的内部状态**，指伪随机数生成器所管理的内存中的数值，请求->根据内部状态计算出数值，并改变内

​	部状态，为下一次生成伪随机数做准备。而**根据内部状态计算出数值+改变内部状态的方法=伪随机数生成算法**

​	**伪随机数生成器的种子**,是指一串随机的比特序列，根据种子就可以生成专属自己的伪随机数列，用于内部状态初始

​	化，伪随机数生成器是公开的，但是种子是保密的。

​	![](.\assets\2019-01-07_191732.png)

### 4.具体的伪随机数生成器

​	**1.杂乱的方法**(不可以)

​	杂乱的算法？那么做事错误的，1.周期，使用复杂算法生成的数列大多数都会有很短的周期。2算法复杂，那么程序

​	员怎么知道其有没有可预测性？

​	**2.线性同余法**（不可以）

​	使用很广的伪随机数生成器算法，但是并不能用于密码技术，不具备不可预测性，不能用于密码技术

​	![](.\assets\2019-01-07_210821.png)

​	**3.单向散列函数法**（可以）

​	![](.\assets\2019-01-07_210923.png)

​	**具备不可预测性，单向散列函数的不可逆性是支撑伪随机数生成器的不可预测性**

​	![](.\assets\2019-01-07_211221.png)

​	**4.密码法**(可以)

​	![](.\assets\2019-01-07_211331.png)

​	即可用对称加密也可以用公钥加密

​	**密码的机密性是支撑伪随机数生成器不可预测性的基础**

​	![](.\assets\2019-01-07_211538.png)

​	**5.ANSI X9.17**（可以）

​		被用于PGP密码软件

​		![](.\assets\2019-01-07_211844.png)

​	![](.\assets\2019-01-07_212040.png)

​	**6.其它算法**

​	是否具有不可预测性，java中可以使用java.security.SecureRandom模块

### 5.对伪随机数生成器的攻击

​	1.对种子攻击

​	因此种子需要保密，不可重现性

​	2.对随机数池进行攻击

​	我们一般不会到了需要的时候才当场生成随机数，而是事先在一个名叫**随机数池**的文件中积累随机比特序列，当密码

​	软件需要种子时，从中取个，因此还需要**保护随机数池**，否则会被推测出种子

## 13.PGP

​	密码技术的完美组合

### 1.简介

​	密码软件，以及另外一款GunPG 遵照OpenGPG（对密文和数字签名格式进行定义的标准规范）规范编写的

​	![](.\assets\2019-01-07_213930.png)

​	PGP功能：对称密码、公钥密码、数字签名、单向散列函数、证书、压缩、文本数据（ASCII radix-64格式，用于邮

​	件与二进制文本之间的转换）、大文件拆分与拼合、钥匙串的管理（管理生成的密钥以及从外部获取的公钥等）

### 2.生成密钥对

### 3.加密和解密

​	![](.\assets\2019-01-07_215200.png)

​	![](.\assets\2019-01-07_215331.png)

### 4.生成和验证数字签名

​	![](.\assets\2019-01-07_220312.png)

​		![](.\assets\2019-01-07_220415.png)

### 5.生成数字签名并加密以及验证

​	![](.\assets\2019-01-07_221919.png)

​		![](.\assets\2019-01-07_222312.png)

### 6.信任网

 确认公钥的合法性，使用的方法，并未使用认证机构，而是建立每个人之间的信任关系，即PGP用户会互相对对方的公

钥进行数字签名（用自己的公钥对别人的公钥进行数字签名，并导入自己的钥匙串，下次进行对比），自己决定信任哪个

公钥，并设置对所有者对应的信任等级（完全信任，有限信任,不信任等）

## 14.SSL/TLS

​	安全的通信

### 1.介绍

​	http 不具备安全性，SSL/TLS作为通信的加密协议，保证了http通信安全，使用伪随机数生成器生成密钥，对称加密

​	加密信息，通过公钥加密/Diffe-Hellman 保护密钥，并使用单向散列函数生成消息认证码，对公钥再加上数字签名生

​	成证书，使用一个大的框架组装起来。SSL/TLS 也可以保护其他协议（邮件发送SMTP 邮件接收POP3），SSL3.0

​	已经不安全（POODLE攻击），TLS是建立在SSL3.0的基础上

### 2.TLS

​	基于TLS 1.2版本步骤，TLS=TLS记录协议（负责压缩加密认证，对称密码+消息认证码）+TLS握手协议（除加密以

​	外的其他操作）

​	![](.\assets\2019-01-07_230915.png)

​		![](.\assets\2019-01-07_232443.png)

1.握手协议：服务端与客户端在密码通信前交换一些必要信息，生成共享密钥以及交换证书，因此使用公钥密码或者

​		Diffie-Hellman密钥交换

​	![](.\assets\2019-01-08_103602.png)

2.密码规格变更协议

​	用与密码切换的同步

3.警告协议

​	用于发生错误时 通知通信对象，握手协议过程中产生异常，或者消息认证码错误、压缩数据无法解压缩等问题时，

​	使用

4.应用数据协议

​	用于通信对象之间传送应用数据

5.主密码

​	用预备密码、客户端随机数和服务器随机数计算出来

​	![](.\assets\2019-01-08_112938.png)

6.小结

![](.\assets\2019-01-08_113037.png)

7.攻击

​	1.**对各个密码技术攻击,**我们可以跟换加密套件

​	2**.OpenSSL心脏出血**，不是SSL/TLS的漏洞，而是OpenSSL这一实现上的漏洞，升级OpenSSL版本，或者禁止

​	在TLS心跳扩展功能（该功能队请求数据大小部进行检查，从而导致误将内存中与该请求无关的信息返回给请求者）

​	3.**SSL3.0漏洞与POODLE攻击** ,禁用SSL3.0,SSL3.0 d	对CBC模式加密时的分组填充操作没有做严格的规定，而且

​	填充数据的完整性没有受到消息认证码的保护，即填充提示攻击

​	4.**FREAK攻击与密码产品出口管理制**，SSL/TLS 上名为RSA Export Suites 强度较低的密码套件（质因分解）。也可

​	以作为中间人攻击。

​	5.**对伪随机数的攻击**，即可预测性

​	6.**利用证书的时间差**    

**注意：** 

1. 即便对方拥有合法的证书，也不代表你就可以放心地发送信用卡号，仅通过SSL/TLS 无法确认对方是否从事信

​	用卡诈骗

2. 密码通信之前的数据不受保护

3. 密码通信之后的数据不受保护

   使用SSL/TLS 信用卡号不会在通信过程中被第三方获取                  

## 15.密码技术与现代社会

​	我们生活在不完美的安全中

​	![](.\assets\2019-01-08_152723.png)

![](.\assets\2019-01-08_152738.png)

![](.\assets\2019-01-08_153346.png)

### 1.比特币

虚拟货币，也叫作密码学货币，可脱离物理介质，仅通过互联网就可以流通。比特币交易时使用的私钥一单遗失，所关联

的比特币就再也无法找回

2.P2P网络

全世界所有比特币用户的计算机共同保存、验证和使用支撑比特体系的所有必要信息，与其说比特币是货币，不如说是一

种基于P2P网络的支付结算系统

3.地址

比特币的交易是在比特币地址之间完成的，交易的地址是由公钥的散列值生成的，每次交易地址不同（当然，捐赠等可以

是一个地址），都是以“1”开头的

4.钱包

比特币交易的客户端，用于生成密钥对和管理，公钥接收比特币，私钥支付比特币。

5.区块链

区块链就是保存比特币全部交易记录的公共账簿，以区块为单位组织起来，保存着每个地址的每次交易记录

![](.\assets\2019-01-08_191715.png)

### 2.量子密码

​	让通信本身不可窃听的技术，利用光子的量子性实现通信。

​	1.光子的偏振无法准确预测偏振方向。

​	2.测量本身会导致光子状态发生改变