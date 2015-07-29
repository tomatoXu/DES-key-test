#include "stdio.h"
#include "memory.h"
#include "time.h"
#include "stdlib.h"
#include "DES.h"
//字节转换成二进制
int ByteToBit(ElemType ch, ElemType bit[8]){
	int cnt;
	for(cnt = 0;cnt < 8; cnt++){
		*(bit+cnt) = (ch>>cnt)&1;
	}
	return 0;
}

//二进制转换成字节
int BitToByte(ElemType bit[8],ElemType *ch){
	int cnt;
	for(cnt = 0;cnt < 8; cnt++){
		*ch |= *(bit + cnt)<<cnt;
	}
	return 0;
}

//将长度为8的字符串转为二进制位串
int Char8ToBit64(ElemType ch[8],ElemType bit[64]){
	int cnt;
	for(cnt = 0; cnt < 8; cnt++){		
		ByteToBit(*(ch+cnt),bit+(cnt<<3));
	}
	return 0;
}

//将二进制位串转为长度为8的字符串
int Bit64ToChar8(ElemType bit[64],ElemType ch[8]){
	int cnt;
	memset(ch,0,8);
	for(cnt = 0; cnt < 8; cnt++){
		BitToByte(bit+(cnt<<3),ch+cnt);
	}
	return 0;
}

//生成子密钥
int DES_MakeSubKeys(ElemType key[64],ElemType subKeys[16][48]){
	ElemType temp[56];
	int cnt;
	DES_PC1_Transform(key,temp);//PC1置换
	for(cnt = 0; cnt < 16; cnt++){//16轮跌代，产生16个子密钥
		DES_ROL(temp,MOVE_TIMES[cnt]);//循环左移
		DES_PC2_Transform(temp,subKeys[cnt]);//PC2置换，产生子密钥
	}
	return 0;
}

//密钥置换1
int DES_PC1_Transform(ElemType key[64], ElemType tempbts[56]){
	int cnt;	
	for(cnt = 0; cnt < 56; cnt++){
		tempbts[cnt] = key[PC_1[cnt]];
	}
	return 0;
}

//密钥置换2
int DES_PC2_Transform(ElemType key[56], ElemType tempbts[48]){
	int cnt;
	for(cnt = 0; cnt < 48; cnt++){
		tempbts[cnt] = key[PC_2[cnt]];
	}
	return 0;
}

//循环左移
int DES_ROL(ElemType data[56], int time){	
	ElemType temp[56];

	//保存将要循环移动到右边的位
	memcpy(temp,data,time);
	memcpy(temp+time,data+28,time);
	
	//前28位移动
	memcpy(data,data+time,28-time);
	memcpy(data+28-time,temp,time);

	//后28位移动
	memcpy(data+28,data+28+time,28-time);
	memcpy(data+56-time,temp+time,time);	

	return 0;
}

//IP置换
int DES_IP_Transform(ElemType data[64]){
	int cnt;
	ElemType temp[64];
	for(cnt = 0; cnt < 64; cnt++){
		temp[cnt] = data[IP_Table[cnt]];
	}
	memcpy(data,temp,64);
	return 0;
}

//IP逆置换
int DES_IP_1_Transform(ElemType data[64]){
	int cnt;
	ElemType temp[64];
	for(cnt = 0; cnt < 64; cnt++){
		temp[cnt] = data[IP_1_Table[cnt]];
	}
	memcpy(data,temp,64);
	return 0;
}

//扩展置换
int DES_E_Transform(ElemType data[48]){
	int cnt;
	ElemType temp[48];
	for(cnt = 0; cnt < 48; cnt++){
		temp[cnt] = data[E_Table[cnt]];
	}	
	memcpy(data,temp,48);
	return 0;
}

//P置换
int DES_P_Transform(ElemType data[32]){
	int cnt;
	ElemType temp[32];
	for(cnt = 0; cnt < 32; cnt++){
		temp[cnt] = data[P_Table[cnt]];
	}	
	memcpy(data,temp,32);
	return 0;
}

//异或
int DES_XOR(ElemType R[48], ElemType L[48] ,int count){
	int cnt;
	for(cnt = 0; cnt < count; cnt++){
		R[cnt] ^= L[cnt];
	}
	return 0;
}

//S盒置换
int DES_SBOX(ElemType data[48]){
	int cnt;
	int line,row,output;
	int cur1,cur2;
	for(cnt = 0; cnt < 8; cnt++){
		cur1 = cnt*6;
		cur2 = cnt<<2;
		
		//计算在S盒中的行与列
		line = (data[cur1]<<1) + data[cur1+5];
		row = (data[cur1+1]<<3) + (data[cur1+2]<<2)
			+ (data[cur1+3]<<1) + data[cur1+4];
		output = S[cnt][line][row];

		//化为2进制
		data[cur2] = (output&0X08)>>3;
		data[cur2+1] = (output&0X04)>>2;
		data[cur2+2] = (output&0X02)>>1;
		data[cur2+3] = output&0x01;
	}	
	return 0;
}

//交换
int DES_Swap(ElemType left[32], ElemType right[32]){
	ElemType temp[32];
	memcpy(temp,left,32);	
	memcpy(left,right,32);	
	memcpy(right,temp,32);
	return 0;
}

//加密单个分组
int DES_EncryptBlock(ElemType plainBlock[8], ElemType subKeys[16][48], ElemType cipherBlock[8]){
	ElemType plainBits[64];
	ElemType copyRight[48];
	int cnt;

	Char8ToBit64(plainBlock,plainBits);		
	//初始置换（IP置换）
	DES_IP_Transform(plainBits);

	//16轮迭代
	for(cnt = 0; cnt < 16; cnt++){		
		memcpy(copyRight,plainBits+32,32);
		//将右半部分进行扩展置换，从32位扩展到48位
		DES_E_Transform(copyRight);
		//将右半部分与子密钥进行异或操作
		DES_XOR(copyRight,subKeys[cnt],48);	
		//异或结果进入S盒，输出32位结果
		DES_SBOX(copyRight);
		//P置换
		DES_P_Transform(copyRight);
		//将明文左半部分与右半部分进行异或
		DES_XOR(plainBits,copyRight,32);
		if(cnt != 15){
			//最终完成左右部的交换
			DES_Swap(plainBits,plainBits+32);
		}
	}
	//逆初始置换（IP^1置换）
	DES_IP_1_Transform(plainBits);
	Bit64ToChar8(plainBits,cipherBlock);
	return 0;
}

//解密单个分组
int DES_DecryptBlock(ElemType cipherBlock[8], ElemType subKeys[16][48],ElemType plainBlock[8]){
	ElemType cipherBits[64];
	ElemType copyRight[48];
	int cnt;

	Char8ToBit64(cipherBlock,cipherBits);		
	//初始置换（IP置换）
	DES_IP_Transform(cipherBits);
	
	//16轮迭代
	for(cnt = 15; cnt >= 0; cnt--){		
		memcpy(copyRight,cipherBits+32,32);
		//将右半部分进行扩展置换，从32位扩展到48位
		DES_E_Transform(copyRight);
		//将右半部分与子密钥进行异或操作
		DES_XOR(copyRight,subKeys[cnt],48);		
		//异或结果进入S盒，输出32位结果
		DES_SBOX(copyRight);
		//P置换
		DES_P_Transform(copyRight);		
		//将明文左半部分与右半部分进行异或
		DES_XOR(cipherBits,copyRight,32);
		if(cnt != 0){
			//最终完成左右部的交换
			DES_Swap(cipherBits,cipherBits+32);
		}
	}
	//逆初始置换（IP^1置换）
	DES_IP_1_Transform(cipherBits);
	Bit64ToChar8(cipherBits,plainBlock);
	return 0;
}

//加密文件
int DES_Encrypt(char plain_input[],int key[64],char cipher_output[]){
	int count = 0;
	ElemType plainBlock[8],cipherBlock[8];
	ElemType bKey[64];
        int k=0;
        for(;k<64;k++){
                bKey[k]=key[k];
        }
	ElemType subKeys[16][48];
	int times=0;
        int p=strlen(plain_input);
        int q=0;
	DES_MakeSubKeys(bKey,subKeys);
   //     printf("the encrypted message:");
	while(p){
                if (q%8==7){
                        plainBlock[q%8]=plain_input[q];
			DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
                        int i = 0;
                        for (;i<8;i++){
                        //        printf("%c",cipherBlock[i]);
                                cipher_output[times*8+i]=cipherBlock[i];
                        }
                        times++;
                        q++;
                }
                else{
                        plainBlock[q%8]=plain_input[q];
                        q++;
                }
                p--;
	}
	if(q%8!=0){
                plainBlock[7]=8-(q%8);
		memset(plainBlock + (q%8),'\0',7 - (q%8));
		DES_EncryptBlock(plainBlock,subKeys,cipherBlock);
                int i = 0;
                for (;i<8;i++){                      	
                      //  printf("%c",cipherBlock[i]);
                        cipher_output[times*8+i]=cipherBlock[i];
                }
        }

	return OK;
}

//解密文件
int DES_Decrypt(char cipher_output[], int key[64],char message[]){
	int count,times = 0;
	int fileLen;
	ElemType plainBlock[8],cipherBlock[8];
	ElemType bKey[64];
        int k=0;
        for(;k<64;k++){
                bKey[k]=key[k];
        }
	ElemType subKeys[16][48];

	//设置密钥
	
	//将密钥转换为二进制流
//	Char8ToBit64(keyBlock,bKey);
	//生成子密钥
        char *t=cipher_output; 
	DES_MakeSubKeys(bKey,subKeys);
	//取文件长度	
	fileLen = strlen(t);	//取文件指针当前位置
        while(1){
		//密文的字节数一定是8的整数倍
                int i;
                for(i=0;i<8;i++){
                        cipherBlock[i]=cipher_output[(8*times+i)];
                }
		DES_DecryptBlock(cipherBlock,subKeys,plainBlock);
		times ++;
		if(times*8 < fileLen){
                        int i;
			for(i=0;i<8;i++){
                                message[8*(times-1)+i]=plainBlock[i];

                        }
                        for(i=0;i<8;i++){
                       //         printf("%c",plainBlock[i]);
                        }
		}
		else{
			break;
		}
	}
	//判断末尾是否被填充
        //
	if(plainBlock[7] < 8){
		for(count = 8 - plainBlock[7]; count < 7; count++){
			if(plainBlock[count] != '\0'){
				break;
			}
		}
	}	
	if(count == 7){//有填充
                int i;
                for(i=0;i<8-plainBlock[7];i++){
                        message[8*(times-1)+i]=plainBlock[i];
                }
        }
	else{//无填充
                int i;
                for(i=0;i<8;i++){
                        message[8*(times-1)+i]=plainBlock[i];
                     //   printf("%c",plainBlock[i]);
                }
                message[8*times]='\0';
	}
        printf("\n");
	return OK;
}


void key(int key[]){
        int i,j,temp;
        srand((unsigned)time(NULL));
        for (i=0;i<64;i++){
                if((i%8)!=7){
                        j=rand()%2;
                        key[i]=j;
                }
        }
        i=0;
        while(i<64){
                if((i%8)==7){
                        temp=0;
                        for(j=i-1;j>i-8;j--){
                                temp+=key[j];
                        }    
                        if(temp%2==0){
                                key[i]=1;
                        }
                        else
                                key[i]=0;
                }
                i++;
        }
        printf("the key is:\n");
        for(i=0;i<64;i++){
                printf("%d ",key[i]);
                if(i%8==7)
                        printf("\n");
        }
}                                                              

















