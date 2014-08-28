/************************************************************************/
/* <���ܿ���ص�ȫ�ֺ�������>                                                 */
/************************************************************************/
#include "swsdsglobalfun.h"


/**
 * �������ݵ��ļ�
 * filename:������ļ���
 * mode:����ʱ�õ��ļ���ʽ
 * buffer:��Ҫ�������ݵ�ָ��
 * size:buffer�����ݳ��ȣ����봫�룬buffer����û�����ݽ�����־
 */
int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	int rw, rwed;

	if ((fp = fopen(filename, mode)) == NULL)
		return 0;

	rwed = 0; // ����ÿ��д���ļ����ַ�����,�˴�rwed = 0���п���һ�ξͰ���������д�뵽�ļ���
	while (size > rwed)
	{
		if ((rw = fwrite(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}
		rwed += rw;
	}
	fclose(fp);
	return rwed;
}

/**
 * ���湫Կ���ݺ�˽Կ���ݵ��ļ�
 *
 */
int save_key_pair_ecc(ECCrefPublicKey *p_public_key, ECCrefPrivateKey *p_private_key)
{
	int ret;

	size_t public_key_len = sizeof(ECCrefPublicKey);
	size_t private_key_len = sizeof(ECCrefPrivateKey);

	ret = FileWrite("public_ecc.key", "wb+", (unsigned char *)p_public_key, public_key_len);
	if(public_key_len != ret)
	{
		print_error_msg(ret, "���湫Կʧ��");
		return ret;
	}
	ret = FileWrite("private_ecc.key", "wb+", (unsigned char *)p_private_key, private_key_len);
	if(private_key_len != ret)
	{
		print_error_msg(ret, "����˽Կʧ��");
		return ret;
	}

	printf("����ɹ�\n");
	return ret;
}




/**
 * ��׼�����붨��
 * ���ݴ��������������Ϣ�����Ҵ�ӡ���ú��������msg��Ϣ
 */
int print_error_msg(int ret, char *msg) 
{
	if (NULL != msg)
		printf("%s \n", msg);
	switch (ret) {
	case SDR_UNKNOWERR:
		printf("δ֪����\n");
		break;

	case SDR_NOTSUPPORT:
		printf("��֧��\n");
		break;

	case SDR_COMMFAIL:
		printf("ͨ�Ŵ���\n");
		break;

	case SDR_HARDFAIL:
		printf("Ӳ������\n");
		break;

	case SDR_OPENDEVICE:
		printf("���豸����\n");
		break;

	case SDR_OPENSESSION:
		printf("�򿪻Ự�������\n");
		break;

	case SDR_PARDENY:
		printf("Ȩ�޲�����\n");
		break;

	case SDR_KEYNOTEXIST:
		printf("��Կ������\n");
		break;

	case SDR_ALGNOTSUPPORT:
		printf("��֧�ֵ��㷨\n");
		break;

	case SDR_ALGMODNOTSUPPORT:
		printf("��֧�ֵ��㷨ģʽ\n");
		break;

	case SDR_PKOPERR:
		printf("��Կ�������\n");
		break;

	case SDR_SKOPERR:
		printf("˽Կ�������\n");
		break;

	case SDR_SIGNERR:
		printf("ǩ������\n");
		break;

	case SDR_VERIFYERR:
		printf("��֤����\n");
		break;

	case SDR_SYMOPERR:
		printf("�Գ��������\n");
		break;

	case SDR_STEPERR:
		printf("�������\n");
		break;

	case SDR_FILESIZEERR:
		printf("�ļ���С������������ݳ��ȷǷ�\n");
		break;

	case SDR_FILENOEXIST:
		printf("�ļ�������\n");
		break;

	case SDR_FILEOFSERR:
		printf("�ļ�����ƫ��������\n");
		break;

	case SDR_KEYTYPEERR:
		printf("��Կ���ʹ���\n");
		break;

	case SDR_KEYERR:
		printf("��Կ����\n");
		break;

		/*��չ������*/
	case SWR_BASE:
		printf("�Զ�����������ֵ\n");
		break;

	case SWR_INVALID_USER:
		printf("��Ч���û���\n");
		break;

	case SWR_INVALID_AUTHENCODE:
		printf("��Ч����Ȩ��\n");
		break;

	case SWR_PROTOCOL_VER_ERR:
		printf("��֧�ֵ�Э��汾\n");
		break;

	case SWR_INVALID_COMMAND:
		printf("�����������\n");
		break;

	case SWR_INVALID_PARAMETERS:
		printf("����������������ݰ���ʽ\n");
		break;

	case SWR_FILE_ALREADY_EXIST:
		printf("�Ѵ���ͬ���ļ�\n");
		break;

	case SWR_SYNCH_ERR:
		printf("�࿨ͬ������\n");
		break;

	case SWR_SYNCH_LOGIN_ERR:
		printf("�࿨ͬ�����¼����\n");
		break;

	case SWR_SOCKET_TIMEOUT:
		printf("��ʱ����\n");
		break;

	case SWR_CONNECT_ERR:
		printf("���ӷ���������\n");
		break;

	case SWR_SET_SOCKOPT_ERR:
		printf("����Socket��������\n");
		break;

	case SWR_SOCKET_SEND_ERR:
		printf("����LOGINRequest����\n");
		break;

	case SWR_SOCKET_RECV_ERR:
		printf("����LOGINRequest����\n");
		break;

	case SWR_SOCKET_RECV_0:
		printf("����LOGINRequest����\n");
		break;

	case SWR_SEM_TIMEOUT:
		printf("��ʱ����\n");
		break;

	case SWR_NO_AVAILABLE_HSM:
		printf("û�п��õļ��ܻ�\n");
		break;

	case SWR_NO_AVAILABLE_CSM:
		printf("���ܻ���û�п��õļ���ģ��\n");
		break;

	case SWR_CONFIG_ERR:
		printf("�����ļ�����\n");
		break;

		/*���뿨������*/
	case SWR_CARD_BASE:
		printf("���뿨������\n");
		break;

	case SWR_CARD_UNKNOWERR:
		printf("δ֪����\n");
		break;

	case SWR_CARD_NOTSUPPORT:
		printf("��֧�ֵĽӿڵ���\n");
		break;

	case SWR_CARD_COMMFAIL:
		printf("���豸ͨ��ʧ��\n");
		break;

	case SWR_CARD_HARDFAIL:
		printf("����ģ������Ӧ\n");
		break;

	case SWR_CARD_OPENDEVICE:
		printf("���豸ʧ��\n");
		break;

	case SWR_CARD_OPENSESSION:
		printf("�����Ựʧ��\n");
		break;

	case SWR_CARD_PARDENY:
		printf("��˽Կʹ��Ȩ��\n");
		break;

	case SWR_CARD_KEYNOTEXIST:
		printf("�����ڵ���Կ����\n");
		break;

	case SWR_CARD_ALGNOTSUPPORT:
		printf("��֧�ֵ��㷨����\n");
		break;

	case SWR_CARD_ALGMODNOTSUPPORT:
		printf("��֧�ֵ��㷨����\n");
		break;

	case SWR_CARD_PKOPERR:
		printf("��Կ����ʧ��\n");
		break;

	case SWR_CARD_SKOPERR:
		printf("˽Կ����ʧ��\n");
		break;

	case SWR_CARD_SIGNERR:
		printf("ǩ������ʧ��\n");
		break;

	case SWR_CARD_VERIFYERR:
		printf("��֤ǩ��ʧ��\n");
		break;

	case SWR_CARD_SYMOPERR:
		printf("�Գ��㷨����ʧ��\n");
		break;

	case SWR_CARD_STEPERR:
		printf("�ಽ���㲽�����\n");
		break;

	case SWR_CARD_FILESIZEERR:
		printf("�ļ����ȳ�������\n");
		break;

	case SWR_CARD_FILENOEXIST:
		printf("ָ�����ļ�������\n");
		break;

	case SWR_CARD_FILEOFSERR:
		printf("�ļ���ʼλ�ô���\n");
		break;

	case SWR_CARD_KEYTYPEERR:
		printf("��Կ���ʹ���\n");
		break;

	case SWR_CARD_KEYERR:
		printf("��Կ����\n");
		break;

	case SWR_CARD_BUFFER_TOO_SMALL:
		printf("���ղ����Ļ�����̫С\n");
		break;

	case SWR_CARD_DATA_PAD:
		printf("����û�а���ȷ��ʽ��䣬����ܵõ����������ݲ���������ʽ\n");
		break;

	case SWR_CARD_DATA_SIZE:
		printf("���Ļ����ĳ��Ȳ�������Ӧ���㷨Ҫ��\n");
		break;

	case SWR_CARD_CRYPTO_NOT_INIT:
		printf("�ô������û��Ϊ��Ӧ���㷨���ó�ʼ������\n");
		break;

		//01/03/09�����뿨Ȩ�޹��������
	case SWR_CARD_MANAGEMENT_DENY:
		printf("����Ȩ�޲�����\n");
		break;

	case SWR_CARD_OPERATION_DENY:
		printf("����Ȩ�޲�����\n");
		break;

	case SWR_CARD_DEVICE_STATUS_ERR:
		printf("��ǰ�豸״̬���������в���\n");
		break;

	case SWR_CARD_LOGIN_ERR:
		printf("��¼ʧ��\n");
		break;

	case SWR_CARD_USERID_ERR:
		printf("�û�ID��Ŀ/�������\n");
		break;

	case SWR_CARD_PARAMENT_ERR:
		printf("��������\n");
		break;

		//05/06�����뿨Ȩ�޹��������
	case SWR_CARD_MANAGEMENT_DENY_05:
		printf("����Ȩ�޲�����\n");
		break;

	case SWR_CARD_OPERATION_DENY_05:
		printf("����Ȩ�޲�����\n");
		break;

	case SWR_CARD_DEVICE_STATUS_ERR_05:
		printf("��ǰ�豸״̬���������в���\n");
		break;

	case SWR_CARD_LOGIN_ERR_05:
		printf("��¼ʧ��\n");
		break;

	case SWR_CARD_USERID_ERR_05:
		printf("�û�ID��Ŀ/�������\n");
		break;

	case SWR_CARD_PARAMENT_ERR_05:
		printf("��������\n");
		break;

		/*����������*/
	case SWR_CARD_READER_BASE:
		printf("���������ʹ���\n");
		break;

	case SWR_CARD_READER_PIN_ERROR:
		printf("�������\n");
		break;

	case SWR_CARD_READER_NO_CARD:
		printf("ICδ����\n");
		break;

	case SWR_CARD_READER_CARD_INSERT:
		printf("IC���뷽�����򲻵�λ\n");
		break;

	case SWR_CARD_READER_CARD_INSERT_TYPE:
		printf("IC���ʹ���\n");
		break;
	default:
		printf("δ֪������--------\n");
		break;
	}
	printf("������ ----> %x,%d",ret, ret);
	return ret;
}



/**
 * ���ܣ��Զ����Ƶ���ʽ��ӡsourceData�е�����
 * itemName��ӡ�����ƣ�dataLengthΪsourceDataָ��ָ�����ݵĳ��ȣ�rowCountһ�д�ӡʮ�����Ƶĸ���
 * ��rowCount = dataLengthʱֻ��ӡһ�У�rowCount = 1ʱ����ӡdataLength��
 */
int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;

	if ((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;

	if (itemName != NULL)
		printf("%s[%d]:\n", itemName, dataLength);

	for (i = 0; i < (int) (dataLength / rowCount); i++) // ��ӡǰi = (int) (dataLength / rowCount)��
	{
		printf("%08x  ", i * rowCount);   //  �б꣬�ڼ���
		for (j = 0; j < (int) rowCount; j++) {
			printf("%02x ", *(sourceData + i * rowCount + j));
		}
		printf("\n");
	}
	if (!(dataLength % rowCount))
		return 0;

	printf("%08x  ", (dataLength / rowCount) * rowCount); //  �б꣬�ڼ���
	for (j = 0; j < (int) (dataLength % rowCount); j++) // ��ӡʣ�²���һ�е����ݣ�����Ϊj = (int)(dataLength % rowCount)
	{
		printf("%02x ", *(sourceData + (dataLength / rowCount) * rowCount + j));
	}
	printf("\n");
	return 0;
}


int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	int rw, rwed;

	if ((fp = fopen(filename, mode)) == NULL)
		return 0;

	rwed = 0;
	while ((!feof(fp)) && (size > rwed)) {
		if ((rw = fread(buffer + rwed, 1, size - rwed, fp)) <= 0) {
			break;
		}
		rwed += rw;
	}
	fclose(fp);
	return rwed;
}