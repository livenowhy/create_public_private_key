
#include "swsdsglobalfun.h"


int print_error_msg(int ret, char *msg);

#define   INPUT_SRGV_ILLEGAL -1

int main(int argc, char **argv)
{
	if(argc <= 3 || atoi(argv[1]) <= 0 || atoi(argv[1]) >= 3)
	{
		printf("输入参数不合法./a.out <算法标识1 or 2 or 3> <需要产生密钥长度>");
		return INPUT_SRGV_ILLEGAL;
	}

	int temp;


	printf("%d %d \n", atoi(argv[1]), atoi(argv[2]));

	unsigned int alg_id; //指定算法标识
	switch(atoi(argv[1]))
	{

	case 1:
		alg_id = SGD_SM2_1;
		break;
	case 2:
		alg_id = SGD_SM2_2;
		break;
	case 3:
		alg_id = SGD_SM2_3;
		break;
	}

	unsigned int key_bits; //指定密钥长度
	key_bits = atoi(argv[2]);

	SGD_HANDLE hDeviceHandle; // 设备句柄

	int ret;
	if(SDR_OK != (ret = SDF_OpenDevice(&hDeviceHandle)))
	{
		print_error_msg(ret, "打开设备失败");
		return 0;
	}

	SGD_HANDLE hSessionHandle;
	if(SDR_OK != (ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle)))
	{
		print_error_msg(ret, "打开回话句柄失败");
		return 0;
	}


// SDF_GenerateKeyPair_ECC(void *hSessionHandle, unsigned int uiAlgID,	unsigned int uiKeyBits,	ECCrefPublicKey *pucPublicKey,	ECCrefPrivateKey *pucPrivateKey)


	ECCrefPublicKey public_key; // ECC 公钥结构
	ECCrefPrivateKey private_key; // ECC 私钥结构

	if(SDR_OK != (ret = SDF_GenerateKeyPair_ECC(hSessionHandle, alg_id, key_bits, &public_key, &private_key)))
	{
		print_error_msg(ret, "生产秘钥失败");
		return 0;
	}

	save_key_pair_ecc(&public_key, &private_key);

	SDF_CloseSession(hSessionHandle);
	SDF_CloseDevice(hDeviceHandle);
	return 0;
}
