#include<stdio.h>
#include <stdlib.h>

typedef unsigned char byte;
typedef unsigned int  uint;
struct bufferStruct{
  byte *b;
  int   l;
};
typedef struct bufferStruct buffer;
void bytesToRawKeys(buffer buf, uint *ka,uint *kb,uint *kc,uint *kd){
  if(buf.l<16){
    exit(1);
  }
  *ka=((uint)buf.b[0])|(((uint)buf.b[4])<<8)|(((uint)buf.b[8])<<16)|(((uint)buf.b[12])<<24);
  *kb=((uint)buf.b[1])|(((uint)buf.b[5])<<8)|(((uint)buf.b[9])<<16)|(((uint)buf.b[13])<<24);
  *kc=((uint)buf.b[2])|(((uint)buf.b[6])<<8)|(((uint)buf.b[10])<<16)|(((uint)buf.b[14])<<24);
  *kd=((uint)buf.b[3])|(((uint)buf.b[7])<<8)|(((uint)buf.b[11])<<16)|(((uint)buf.b[15])<<24);
}
void printfHex(buffer buf){
  for(int i=0; i<buf.l; i++){
    printf("%02X",buf.b[i]);
  }
  printf("\n");
}

buffer xorKeyStream(uint *rawKeys[4], buffer buf){
  int counter=0;
  buffer result={.l=buf.l,.b=malloc(buf.l)};
  uint *a=rawKeys[0],*b=rawKeys[1],*c=rawKeys[2],*d=rawKeys[3];
  for(;counter<buf.l;){
    *a+=*b,*d^=*a,*d=(*d<<16)|(*d>>16),*c+=*d,*b^=*c,*b=(*b<<12)|(*b>>20);
    *a+=*b,*d^=*a,*d=(*d<<8)|(*d>>24),*c+=*d,*b^=*c,*b=(*b<<7)|(*b>>25);
    byte *key=malloc(16);
    key[0]=(byte)*a,key[1]=(byte)(*a>>8),key[2]=(byte)(*a>>16),key[3]=(byte)(*a>>24);
    key[4]=(byte)*b,key[5]=(byte)(*b>>8),key[6]=(byte)(*b>>16),key[7]=(byte)(*b>>24);
    key[8]=(byte)*c,key[9]=(byte)(*c>>8),key[10]=(byte)(*c>>16),key[11]=(byte)(*c>>24);
    key[12]=(byte)*d,key[13]=(byte)(*d>>8),key[14]=(byte)(*d>>16),key[15]=(byte)(*d>>24);
    for(int i=0; i<16 && counter<buf.l; i++){
      result.b[counter]=buf.b[counter]^key[i];
      counter++;
    }
    free(key);
  }
  return result;
}

buffer flexLenScan(){
  buffer result={.l=0};
  for(;;){
    char c;
    scanf("%c",&c);
    if(c=='\n'){
      break;
    }
    if(c==8){
      if(result.l==1){
        result.l=0;
        free(result.b);
      }
      if(result.l>0){
        byte *temp=result.b;
        result.l--;
        result.b=malloc(result.l);
        for(int i=0; i<result.l; i++){
          result.b[i]=temp[i];
        }
        free(temp);
      }
      continue;
    }
    if(result.l==0){
      result.b=malloc(1);
      result.b[0]=(byte)c;
      result.l++;
    }else{
      byte *temp=result.b;
      result.l++;
      result.b=malloc(result.l);
      for(int i=0; i<result.l-1; i++){
        result.b[i]=temp[i];
      }
      free(temp);
      result.b[result.l-1]=(byte)c;
    }
  }
  return result;
}

buffer to16BytesHash(buffer buf){
  buffer result={.l=16,.b=malloc(result.l)};
  for(int i=0; i<result.l; i++){
    result.b[i]=0xff;
  }
  byte b0=buf.b[0];
  for(int i=0; i<buf.l; i++){
    if(i+1<buf.l){
      buf.b[i]-=buf.b[i+1];
    }else{
      buf.b[i]-=b0;
    }
  }
  b0=0xff;
  for(int i=0; i<buf.l; i++){
    int j=i%result.l;
    b0^=buf.b[i]-((b0<<4)|(b0>>4));
    result.b[j]=b0;
    if(result.b[j]+1>result.b[j]){
      result.b[j]++;
    }
  }
  return result;
}

int main(){
  printf("input key       :");
  buffer key=flexLenScan();
  if(key.l<16){
    byte *temp=key.b;
    key.b=malloc(16);
    for(int i=0; i<key.l; i++){
      key.b[i]=temp[i];
    }
    key.l=16;
    free(temp);
    /*byte *_key=malloc(16);
    for(int i=0;i<key.l;i++){
      _key[i]=key.b[i];
    }
    key.l=16;
    *key.b=*_key;*/
    //free(_key); //sigsegv
  }
  buffer hashedKey=to16BytesHash(key);
  printf("hashed key (hex):");
  printfHex(hashedKey);
  uint a,b,c,d;
  uint *encKey[4]={&a,&b,&c,&d};
  bytesToRawKeys(hashedKey,&a,&b,&c,&d);
  printf("input plaintext :");
  buffer buf=flexLenScan();
  printf("plaintext (hex) :");
  printfHex(buf);
  printf("ciphertext (hex):");
  buffer encrypted=xorKeyStream(encKey,buf);
  printfHex(encrypted);
  //printfHex(xorKeyStream(encKey,buf));
  bytesToRawKeys(hashedKey, &a,&b,&c,&d);
  printf("decrypted (hex) :");
  buffer decrypted=xorKeyStream(encKey,encrypted);
  printfHex(decrypted);
  printf("decrypted       :%s\n",decrypted.b);
  free(key.b);
  free(buf.b);
  free(encrypted.b);
  free(decrypted.b);
  free(hashedKey.b);
  return 0;
}

