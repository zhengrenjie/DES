#include "encrypt_DES.h"


encrypt_DES::encrypt_DES(int key[64])
{
	m_SetKEY(key);
	m_SetSubKey();
}

encrypt_DES::~encrypt_DES()
{
}

void encrypt_DES::SetText(int n[64])
{
	if(m_workmode==_ENCRYPT)
	{
		for(int i=0;i<64;i++)
		{
			m_plaintext[i]=n[i];
		}
	}else if(m_workmode==_DECRYPT)
	{
		for(int i=0;i<64;i++)
		{
			m_encryptresult[i]=n[i];
		}
	}
}

void encrypt_DES::SetWorkMode(MODE n)
{
	m_workmode=n;
}

void encrypt_DES::Run()
{
	if(_ENCRYPT==m_workmode)
	{
		m_Encrypt();
	}
	else if(m_workmode==_DECRYPT)
	{
		m_Decrypt();
	}
}

void encrypt_DES::m_Encrypt()
{
	int Li[32];
	int Ri[32];
	int *temp_f_result;
	int ciphertext_temp[64];
	int plaintext_temp[64];

	//IP变换
	for(int i=0;i<64;i++)
	{
		plaintext_temp[i]=m_plaintext[IP[i]-1];
	}

	//取出Li和Ri
	for(int i=0;i<32;i++)
	{
		Li[i]=plaintext_temp[i];
		Ri[i]=plaintext_temp[i+32];
	}
	//16次迭代运算
	for(int i=0;i<16;i++)
	{
		int temp[32];
		//Li=Ri
		for(int j=0;j<32;j++)
		{
			temp[j]=Li[j];
			Li[j]=Ri[j];
		}
		//f运算
		temp_f_result=m_pf(Ri,i);
		//异或运算
		for(int j=0;j<32;j++)
		{
			Ri[j]=temp[j]^(*(temp_f_result+j));
		}
	}
	//合并Ri和Li
	for(int i=0;i<32;i++)
	{
		m_encryptresult[i]=Ri[i];
		m_encryptresult[i+32]=Li[i];
	}
	//IP逆运算
	for(int i=0;i<64;i++)
	{
		ciphertext_temp[i]=m_encryptresult[_IP[i]-1];
	}
	for(int i=0;i<64;i++)
	{
		m_encryptresult[i]=ciphertext_temp[i];
	}
}

void encrypt_DES::m_Decrypt()
{
	int Li[32];
	int Ri[32];
	int *temp_f_result;
	int ciphertext_temp[64];
	int decryptresult_temp[64];

	//IP变换
	for(int i=0;i<64;i++)
	{
		ciphertext_temp[i]=m_encryptresult[IP[i]-1];
	}

	//取出Li和Ri
	for(int i=0;i<32;i++)
	{
		Li[i]=ciphertext_temp[i];
		Ri[i]=ciphertext_temp[i+32];
	}
	//16次迭代运算
	for(int i=0;i<16;i++)
	{
		int temp[32];
		//Li=Ri
		for(int j=0;j<32;j++)
		{
			temp[j]=Li[j];
			Li[j]=Ri[j];
		}
		//f运算
		temp_f_result=m_pf(Ri,15-i);
		//异或运算
		for(int j=0;j<32;j++)
		{
			Ri[j]=temp[j]^(*(temp_f_result+j));
		}
	}
	//合并Ri和Li
	for(int i=0;i<32;i++)
	{
		m_decryptresult[i]=Ri[i];
		m_decryptresult[i+32]=Li[i];
	}
	//IP逆运算
	for(int i=0;i<64;i++)
	{
		decryptresult_temp[i]=m_decryptresult[_IP[i]-1];
	}
	for(int i=0;i<64;i++)
	{
		m_decryptresult[i]=decryptresult_temp[i];
	}
}

int* encrypt_DES::m_pf(int Ri[32],int index)
{
	int Ri_temp[48];
	int result_temp[32];
	int result[32];
	//E运算
	for(int i=0;i<48;i++)
	{
		Ri_temp[i]=Ri[E[i]-1];
	}
	//子密匙和Ri_temp异或
	for(int i=0;i<48;i++)
	{
		Ri_temp[i]=Ri_temp[i]^m_Key[index][i];
	}
	//8个盒子
	for(int i=0;i<8;i++)
	{
		int temp_col=Ri_temp[i*6+1]*8+Ri_temp[i*6+2]*4+Ri_temp[i*6+3]*2+Ri_temp[i*6+4];
		int temp_row=Ri_temp[i*6+0]*2+Ri_temp[i*6+5];

		switch(S[i][temp_row*16+temp_col])
		{
		case 0:result[i*4+0]=0;  result[i*4+1]=0;  result[i*4+2]=0;  result[i*4+3]=0;  break;
		case 1:result[i*4+0]=0;  result[i*4+1]=0;  result[i*4+2]=0;  result[i*4+3]=1;  break;
		case 2:result[i*4+0]=0;  result[i*4+1]=0;  result[i*4+2]=1;  result[i*4+3]=0;  break;
		case 3:result[i*4+0]=0;  result[i*4+1]=0;  result[i*4+2]=1;  result[i*4+3]=1;  break;
		case 4:result[i*4+0]=0;  result[i*4+1]=1;  result[i*4+2]=0;  result[i*4+3]=0;  break;
		case 5:result[i*4+0]=0;  result[i*4+1]=1;  result[i*4+2]=0;  result[i*4+3]=1;  break;
		case 6:result[i*4+0]=0;  result[i*4+1]=1;  result[i*4+2]=1;  result[i*4+3]=0;  break;
		case 7:result[i*4+0]=0;  result[i*4+1]=1;  result[i*4+2]=1;  result[i*4+3]=1;  break;
		case 8:result[i*4+0]=1;  result[i*4+1]=0;  result[i*4+2]=0;  result[i*4+3]=0;  break;
		case 9:result[i*4+0]=1;  result[i*4+1]=0;  result[i*4+2]=0;  result[i*4+3]=1;  break;
		case 10:result[i*4+0]=1; result[i*4+1]=0;  result[i*4+2]=1;  result[i*4+3]=0;  break;
		case 11:result[i*4+0]=1; result[i*4+1]=0;  result[i*4+2]=1;  result[i*4+3]=1;  break;
		case 12:result[i*4+0]=1; result[i*4+1]=1;  result[i*4+2]=0;  result[i*4+3]=0;  break;
		case 13:result[i*4+0]=1; result[i*4+1]=1;  result[i*4+2]=0;  result[i*4+3]=1;  break;
		case 14:result[i*4+0]=1; result[i*4+1]=1;  result[i*4+2]=1;  result[i*4+3]=0;  break;
		case 15:result[i*4+0]=1; result[i*4+1]=1;  result[i*4+2]=1;  result[i*4+3]=1;  break;
		}
	}
	//P运算
	for(int i=0;i<32;i++)
	{
		result_temp[i]=result[P[i]-1];
	}

	for(int i=0;i<32;i++)
	{
		result[i]=result_temp[i];
	}

	return result;
}

int* encrypt_DES::m_pEncryptResult()
{
	return m_encryptresult;
}

int* encrypt_DES::m_pDecryptResult()
{
	return m_decryptresult;
}

void encrypt_DES::m_SetSubKey()
{
	int KEY_temp[56];
	//PC_1变换
	for(int i=0;i<56;i++)
	{
		KEY_temp[i]=m_KEY[PC_1[i]-1];
	}

	for(int i=0;i<16;i++)
	{
		//移位
		switch (SHIFT_N[i])
		{
		case 1:
			{
				int temp1=KEY_temp[0];
				int temp2=KEY_temp[28];
				for(int k=0;k<55;k++)
				{
					KEY_temp[k]=KEY_temp[k+1];
				}
				KEY_temp[55]=temp2;
				KEY_temp[27]=temp1;
				break;}
		case 2:
			{
				int temp1=KEY_temp[0];
				int temp2=KEY_temp[1];
				int temp3=KEY_temp[28];
				int temp4=KEY_temp[29];
				for(int k=0;k<54;k++)
				{
					KEY_temp[k]=KEY_temp[k+2];
				}
				KEY_temp[55]=temp4;
				KEY_temp[54]=temp3;
				KEY_temp[27]=temp2;
				KEY_temp[26]=temp1;
				break;}
		default: break;
		}
		//PC_2变换
		for(int j=0;j<48;j++)
		{
			m_Key[i][j]=KEY_temp[PC_2[j]-1];
		}
	}//for(int i=0;i<16;i++)
}

void encrypt_DES::PrintKey()
{
	for(int i=0;i<16;i++)
	{
		cout<<"Key"<<i<<":"<<endl;
		for(int j=0;j<48;j++)
		{
			cout<<m_Key[i][j];
		}
		cout<<endl;
	}
}

void encrypt_DES::m_SetKEY(int key[64])
{
	for(int i=0;i<64;i++)
	{
		m_KEY[i]=key[i];
	}
}

int* encrypt_DES::pResult()
{
	if(m_workmode==_ENCRYPT)
	{
		return m_pEncryptResult();
	}
	else if(m_workmode==_DECRYPT)
	{
		return m_pDecryptResult();
	}
}
