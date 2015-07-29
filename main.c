#include <stdio.h> 
#include <string.h>
#include "memory.h"  
#include "time.h"  
#include "stdlib.h"
int main()
{	
	clock_t a,b;
	a = clock();
        int key_creat[64];
        key(key_creat);
        char *plain;
        char *cipher;
        char *decrypted_mes;
        char plain_input[256]="";
        char cipher_output[256]="";
        char message[256]="";
        int i = 0;
        printf("please input the content to be encrypted:\n");
        scanf("%s",plain_input);
	DES_Encrypt(plain_input,key_creat,cipher_output);
	b = clock();
	printf("\n加密消耗%d毫秒\n",b-a);
	cipher = cipher_output;
        printf("\nthe encrypted message:\n%s\n",cipher);
//	system("pause");
	a = clock();
	DES_Decrypt(cipher_output,key_creat,message);
	b = clock();
	printf("\n解密消耗%d毫秒\n",b-a);
        decrypted_mes=message;
        printf("\nthe decrypted message:\n%s\n",decrypted_mes);
	getchar();
	return 0;
}
