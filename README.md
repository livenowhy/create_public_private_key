####  产生公钥和私钥对并保存到文件

    ./create  x   xxx
    第一个参数代表采用那种方式生产秘钥

    x = 1 SGD_SM2_1-->椭圆曲线签名算法
    x = 2 SGD_SM2_2-->椭圆曲线密钥交换协议
    x = 3 SGD_SM2_3-->椭圆曲线加密算法

    第二个参数代表需要产生密钥长度

    注意：-lswsds时需要使用libswsds.so
    .......\兼容支持SWCSM18卡\接口库及API文档\linux\common\32下的libswsds.so.SM2_SM3_HD_Soft_EX.3.1.5.0_x86拷贝到/usr/bin命名为libswsds.so

    公钥public_ecc.key
    私钥private_ecc.key

    


	/**
	 * 保存数据到文件
	 * filename:保存的文件名
	 * mode:保存时用的文件格式
	 * buffer:需要保存数据的指针
	 * size:buffer的数据长度，必须传入，buffer可能没有数据结束标志
	 */
	int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size);

	/**
	 * 保存公钥数据和私钥数据到文件
	 *
	 */
	int save_key_pair_ecc(ECCrefPublicKey *p_public_key, ECCrefPrivateKey *p_private_key);

	/**
	 * 标准错误码定义
	 * 根据错误码输出错误信息，并且打印调用函数传入的msg信息
	 */
	int print_error_msg(int ret, char *msg);

	/**
	 * 功能：以二进制的形式打印sourceData中的内容
	 * itemName打印的名称，dataLength为sourceData指针指向数据的长度，rowCount一行打印十六进制的个数
	 * 当rowCount = dataLength时只打印一行；rowCount = 1时，打印dataLength行
	 */
	int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount);

	int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size);
