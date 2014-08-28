/************************************************************************/
/* <���ܿ���ص�ȫ�ֺ�������>                                                 */
/************************************************************************/
#include "swsds.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

/**
 * �������ݵ��ļ�
 * filename:������ļ���
 * mode:����ʱ�õ��ļ���ʽ
 * buffer:��Ҫ�������ݵ�ָ��
 * size:buffer�����ݳ��ȣ����봫�룬buffer����û�����ݽ�����־
 */
int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size);

/**
 * ���湫Կ���ݺ�˽Կ���ݵ��ļ�
 *
 */
int save_key_pair_ecc(ECCrefPublicKey *p_public_key, ECCrefPrivateKey *p_private_key);


/**
 * ��׼�����붨��
 * ���ݴ��������������Ϣ�����Ҵ�ӡ���ú��������msg��Ϣ
 */
int print_error_msg(int ret, char *msg);

/**
 * ���ܣ��Զ����Ƶ���ʽ��ӡsourceData�е�����
 * itemName��ӡ�����ƣ�dataLengthΪsourceDataָ��ָ�����ݵĳ��ȣ�rowCountһ�д�ӡʮ�����Ƶĸ���
 * ��rowCount = dataLengthʱֻ��ӡһ�У�rowCount = 1ʱ����ӡdataLength��
 */
int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount);

int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size);