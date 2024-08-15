/*
/**********************************************************
   TEA2 - (Tiny Encryption Algorithm 2)
   
   TEA Feistel cipher by David Wheeler & Roger M. Needham
   TEA2 by Alexander PUKALL 2006
   
   128-bit block cipher (like AES) 256-bit key 128 rounds
   
   Code free for all, even for commercial software
   
   Compile with gcc : gcc tea2.c -o tea2
   
 **********************************************************/

/**********************************************************
   Input values: 	k[4]	  256-bit key
					v[2]    128-bit plaintext block
   Output values:	v[2]    128-bit ciphertext block 
 **********************************************************/

#include <stdint.h>
#include <stdio.h>

void encrypt (uint64_t v[2], const uint64_t k[4]) {
    uint64_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint64_t delta=0x9E3779B97F4A7C15;     
    uint64_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   
    for (i=0; i<64; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<14) + k0) ^ (v1 + sum) ^ ((v1>>15) + k1);
        v1 += ((v0<<14) + k2) ^ (v0 + sum) ^ ((v0>>15) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint64_t v[2], const uint64_t k[4]) {
    uint64_t v0=v[0], v1=v[1], sum=0x8DDE6E5FD29F0540, i;  /* set up; sum is (delta << 6) & 0xFFFFFFFFFFFFFFFF */
    uint64_t delta=0x9E3779B97F4A7C15;                      
    uint64_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<64; i++) {                         /* each iteration of the loop does two Feistel-cipher rounds */
        v1 -= ((v0<<14) + k2) ^ (v0 + sum) ^ ((v0>>15) + k3);
        v0 -= ((v1<<14) + k0) ^ (v1 + sum) ^ ((v1>>15) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}


void main()
{
  uint64_t v[2];
  uint64_t k[4];
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000000;
 
  printf("TEA2 by Alexander PUKALL 2006 \n 128-bit block 256-bit key 128 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on TEA by David Wheeler & Roger M. Needham\n\n");
  
  printf("Encryption 1\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000001;
  
  printf("Encryption 2\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000001;
  v[1]=0x0000000000000001;
  
  printf("Encryption 3\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
   
}

/*

Encryption 1
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000000
Ciphertext:D713374DD796B948 93E198C8BF480EEA
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000001
Ciphertext:85B25256E406EF80 88B6D9C61E7C08F1
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000001 0000000000000001
Ciphertext:9F6CCED0EAF20C18 CA4F15379C175F5C
Decrypted: 0000000000000001 0000000000000001

*/
