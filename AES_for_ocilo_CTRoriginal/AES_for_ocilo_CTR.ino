#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#define PINNUM  5

#define Nb 4
// The number of 32 bit words in a key.
#define Nk 4
// Key length in bytes [128 bit]
#define KEYLEN 16
// The number of rounds in AES Cipher.
#define Nr 10

/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/


// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];
static state_t* state;

// The array that stores the round keys.
static uint8_t RoundKey[176];

// The Key input to the AES Program
static const uint8_t* Key;

int count;
uint8_t carry = 0x00;
int data_count;
int iterNum = 0;
uint8_t key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//uint8_t in[16]  = {0x00, };
uint8_t in[16];
char io[16]; //10ラウンド目のカギを表示させるのに使う
char iot[16]; //親のカギを表示させるのに使う
uint8_t one_byte = 0x00;
int random_round10_create = 0; //10ラウンド目の鍵1バイト目を決定するのに参照する変数
int loop_count = 0; //random_round10_create + loop_count分までの鍵の処理を行う
int pt_number = 20; //N_pt(平文の数)を設定する変数

uint8_t Nonce[8];
uint64_t CTR[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};




static const uint8_t sbox[256] =   {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t Rcon[255] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
  0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
  0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
  0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
  0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
  0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
  0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
  0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
  0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
  0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
  0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
  0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
  0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
  0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
  0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
struct CtrBlk{ //全128ビットで構成されるカウンタブロックの構造体を定義，全暗号化過程でこの数値は共通していると思う
  //ケースクライアント
  int client_write_IV; //下位48ビット6byte
  //ケースサーバ：
  int server_write_IV; //下位48ビット6byte
  int seq_num; //いらないかもしれない．
  int blk_ctr;  //1で初期化されていたものがブロックごとにインクリメントされていく．処理されたレコードごとに値は初期化されるが，ここではレコードは考えなくてよい
};




void CtrBlk_pt(unsigned char *pt){

    for (int i = 0; i < 16; i++) {
      if (i < 8){
      pt[i] = random() % 256;
    }else if(8 <= i && i < 15){
      pt[i] = 0x00;
    }else{
      pt[15] = 0x01;
    }
}
}



static void CTR_Cipher(uint8_t* CTR_output, const uint8_t* output, const uint8_t* CTR_xor_pt){

  for (int i = 0; i < 16; i++) {
    CTR_output[i] = output[i] ^ CTR_xor_pt[i];
  }
}









static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}




// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states.
static void KeyExpansion(void)
{
  uint32_t i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations

  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0]; //グローバルで宣言したroundkeyにKeyから計算した値を代入していく（すべてのラウンドに対して処理を行う）
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (; (i < (Nb * (Nr + 1))); ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      tempa[j] = RoundKey[(i - 1) * 4 + j];
    }
    if (i % Nk == 0)
    {
      // This function rotates the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        k = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = k;
      }

      // SubWord() is a function that takes a four-byte input word and
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] =  tempa[0] ^ Rcon[i / Nk];
    }
    else if (Nk > 6 && i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
    RoundKey[i * 4 + 0] = RoundKey[(i - Nk) * 4 + 0] ^ tempa[0];
    RoundKey[i * 4 + 1] = RoundKey[(i - Nk) * 4 + 1] ^ tempa[1];
    RoundKey[i * 4 + 2] = RoundKey[(i - Nk) * 4 + 2] ^ tempa[2];
    RoundKey[i * 4 + 3] = RoundKey[(i - Nk) * 4 + 3] ^ tempa[3];
  }
}





void round10key_equal_parentkey(){
  uint8_t i;
  for (i = 0; i < 16; ++i)
  {
    RoundKey[i + 160] = Key[i];
  }
}





void keychange(){
  key[0] = random_round10_create;
  int i;
  //random(0,30000);
  for(i = 1; i < 16; i++){
    key[i] = random() % 256;
  }
  //random_round10_create++;
}




static void AddRoundKey(uint8_t round)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[round * Nb * 4 + i * Nb + j];
    }
  }
// This function adds the round key to state.
// The round key is added to the state by an XOR function.
}





// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(void)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}






// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(void)
{
  uint8_t temp;

  // Rotate first row 1 columns to left
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp       = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp       = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}





static uint8_t xtime(uint8_t x)
{
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}






// MixColumns function mixes the columns of the state matrix
static void MixColumns(void)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;        Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}





// Multiply is used to multiply numbers in the field GF(2^8)
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
          ((y >> 1 & 1) * xtime(x)) ^
          ((y >> 2 & 1) * xtime(xtime(x))) ^
          ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}


static void Cipher(void)
{
  uint8_t round = 0;



/*****************************************************************************/
/*                             親鍵を表示させる                              */
/*****************************************************************************/
 uint8_t s;
 Serial.print("parentkey  : ");
for(s=0; s<16; s++){
  sprintf(io, "%02x", Key[s]);
  Serial.print(io);
}
Serial.print("\n");
/*****************************************************************************/


  //digitalWrite(PINNUM, HIGH);
  
/*
  AddRoundKey(0);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(1);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(2);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(3);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(4);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(5);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(6);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(7);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(8);

  SubBytes();
  ShiftRows();
  MixColumns();
  AddRoundKey(9);

*/
  digitalWrite(PINNUM, HIGH);
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);

  digitalWrite(PINNUM, LOW);

/*****************************************************************************/
/* ラウンド１０の部分鍵を表示させる                                            */
/*****************************************************************************/
 uint8_t i;
 Serial.print("round10key : ");
for(i=160; i<176; i++){
  sprintf(io, "%02x", RoundKey[i]);
  Serial.print(io);
}
Serial.print("\n");
/*****************************************************************************/

  /*
    for (round = 1; round < Nr; ++round)
    {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(round);
    }

    // The last round is given below.
    // The MixColumns function is not here in the last round.
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
  */
}






static void BlockCopy(uint8_t* output, const uint8_t* input)
{
  uint8_t i;
  for (i = 0; i < KEYLEN; ++i)
  {
    output[i] = input[i];
  }
}






//Increasing plaintext value
void increase_pt(uint8_t *pt) {
  int i = 0;

  uint8_t tmp = 0x00;


  for (i = 15; i >= 0; i--) {
    if (i == 15) {
      pt[i] = pt[i] + 0x01;
    } else {
      pt[i] = pt[i] + carry;
    }

    if (count == 0xFF) {
      carry = 0x01;
      count = 0;
    } else {
      carry = 0x00;
    }
  }
  count++;

}






//Creating random plaintext value これはincrease_ptとどっちかつかう?そもそも使われてないかも
static void creat_random_pt(unsigned char* pt){
  for (int i = 0; i <16; i++) {
    pt[i] = random() % 256;
  } 

}






uint8_t ASCII_code(unsigned char a) {
  uint8_t result;
  switch (a) {
    case 0x30: result = 0x00; break;
    case 0x31: result = 0x01; break;
    case 0x32: result = 0x02; break;
    case 0x33: result = 0x03; break;
    case 0x34: result = 0x04; break;
    case 0x35: result = 0x05; break;
    case 0x36: result = 0x06; break;
    case 0x37: result = 0x07; break;
    case 0x38: result = 0x08; break;
    case 0x39: result = 0x09; break;

    case 0x41: result = 0x0A; break;
    case 0x42: result = 0x0B; break;
    case 0x43: result = 0x0C; break;
    case 0x44: result = 0x0D; break;
    case 0x45: result = 0x0E; break;
    case 0x46: result = 0x0F; break;

    default: result = 0x00;
  }
  return result;
}

/*void change_key(){
  for(one_byte=0; one_byte <= ff; one_byte++)
}*/





/*****************************************************************************/
/*                            AES128_ECB_encrypt                             */
/*****************************************************************************/
void AES128_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output)
{
  // Copy input to output, and work in-memory on output
  BlockCopy(output, input);
  state = (state_t*)output;
  keychange();      //ラウンド10の部分鍵1バイト目を順に変えていき、15バイトはランダム生成
  Key = key;
  round10key_equal_parentkey();
  //KeyExpansion();

  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher();
}



/*****************************************************************************/
/*                                 serialEvent                               */
/*****************************************************************************/

void serialEncryption(int pt_number) {
  randomSeed(analogRead(0));
  
  char ioc[16];
  int i = 0;
  int j = 0;
  char input;
  char pt_char;

  uint8_t out[] = {0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97};     //使われていない
  uint8_t output[16] = {0x00, };
  uint8_t CTR_output[16] = {0x00, };
  uint8_t plain[16] = {0x00, };   //使われていない

  //  String test = "";
  char ch_test[33];
  unsigned char data[32];
  unsigned char tmp[2] = {0x0, };
  unsigned int idx = 0;
  int byte_num = 0;
  int data_idx = 0;
  uint8_t tmp_data[32];

  //while (Serial.available()) {
  //input = (char)Serial.read();

  //if (input == 'I') {
  //test = Serial.readString();
  //iterNum = test.toInt();
  //iterNum = 1;
  //Serial.println(test);
  //Serial.println(iterNum, DEC);
  //}
  //else if (input == 'P') {
  //Receiving plaintext from PC
  //test = Serial.readString();
  //Serial.println(test);



  unsigned char test[] = {0x52, 0xe2, 0x30, 0xd0, 0xae, 0xdd, 0x13, 0x7a, 0xbc, 0xea, 0x55, 0xb8, 0x0e, 0xa0, 0xfc, 0xce};
  unsigned char CTR_xor_pt[] = {0x52, 0xe2, 0x30, 0xd0, 0xae, 0xdd, 0x13, 0x7a, 0xbc, 0xea, 0x55, 0xb8, 0x0e, 0xa0, 0xfc, 0xce};
  //test[16] = creat_random_pt(test);//入力の初期値を決めているに過ぎない．下のコードでインクリメントしたりしている．
  CtrBlk_pt(test);
  creat_random_pt(CTR_xor_pt);
  int ave = 1;
  int N_pt = pt_number;           //使用する平文の種類数
  int N_ave = 1;           //1つの平文当たりいくらの波形をとるか

  for (int ipt = 0; ipt < N_pt * N_ave; ipt++) {      //ここでloop回数つまり波形の数を決めている　

    /* for (idx = 0 ; idx < 16; idx++) {
       // test.getBytes(&data[idx], 2, idx);
       //tmp_data[idx] = ASCII_code(test[idx + ipt * 32]);
       tmp_data[idx] = test[idx + ipt * 16];
      }
    */
    for (i = 0; i < 16; i += 1) {       //in[]=test[]つまりtestを平文inに入れている
      // in[i] = tmp_data[i];
      in[i] = test[i];

      //in[i/2] = (uint8_t)((tmp_data[i] << 4) | (tmp_data[i + 1]));
      //Serial.print(in[i / 2], HEX);
      //Serial.print(" ");
    }
    //Serial.println();





/*****************************************************************************/
/* ラウンド１０の部分鍵を表示させる                                            */
/*****************************************************************************/
    Serial.print("TraceNumber(DEC): ");
    Serial.print(random_round10_create);
    Serial.print("\n");
    Serial.print("TraceNumber(HEX): ");
    Serial.print(random_round10_create,HEX);
    Serial.print("\n");
/*****************************************************************************/

    Serial.print("CTL_Block  : ");
    for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x", in[j]);
      Serial.print(ioc);
    }
    Serial.print("\n");
    /*
      Serial.print("P1: ");
      for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x ", in[j]);
      Serial.print(ioc);
      }
      Serial.println();

      Serial.print("Data: ");
      for(i=0; i<32; i++){
      Serial.print(tmp_data[i], HEX);
      }
      Serial.println();
    */

    //AES setting for AES-128
    //BlockCopy(output, in);
    //state = (state_t*)output;

    //Serial.print("iterNum: ");
    //Serial.println(iterNum, DEC);

    /*
      Serial.print("P2: ");
      for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x ", in[j]);
      Serial.print(ioc);
      }
      Serial.println();
    */

    //AES Key-Expansion
    // Key = key;
    //KeyExpansion();

    //  for (i = 0; i < iterNum; i++) {
    //Serial.println(i, DEC);
    //AES-Encryption
    AES128_ECB_encrypt(in, key, output);                //AES128_ECB_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output)
    CTR_Cipher(CTR_output, output, CTR_xor_pt);

    Serial.print("CipherText : ");
    for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x", output[j]);
      Serial.print(ioc);
    }

    Serial.print("\n");

    Serial.print("CTR_xor_pt : ");
    for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x", CTR_xor_pt[j]);
      Serial.print(ioc);
    }
    
    Serial.print("\n");

    Serial.print("CTR Chiptx : ");
    for (j = 0; j < 16; j++) {
      sprintf(ioc, "%02x", CTR_output[j]);
      Serial.print(ioc);
    }

    
    Serial.print("\n");
    Serial.print("\n");

    //  Serial.println();

    if (ave == N_ave) {//既定の平文数を使ったら（このプログラムでは1にしているはず）
      //for(int a = 0;a < 16;a++){
        //test[a] = random() % 256;
      //}
      for(int a = 0;a < 16;a++){
        CTR_xor_pt[a] = random() % 256;
      }
      ave = 0;
    }
    ave = ave + 1;
    delay(100);
    if (ipt == N_ave * N_pt) {
      break;
    }
  }
  //}else{
  //break;
  //}

}

//}








void serialEvent(int stop_triga){

  //CTR_mord();

  if(stop_triga == 1){
    Serial.println("SerialEventが実行されました");
    Serial.println("初回のSerialEncryptionが実行されました");
    serialEncryption(pt_number);
    Serial.println("初回のSerialEncryptionが終了しました");
    //Serial.print("SerialEvent : ");
    //Serial.println(random_round10_create);
    
    for(int i = 0;i < loop_count;i++){
      random_round10_create++;
      Serial.println("serialEncryptionが実行されました");
      serialEncryption(pt_number);
      Serial.println("SerialEncryptionが終了しました");
    }
    
  }else{
    Serial.println("SerialEventが異常実行されました");
    Serial.println("SerialEventの異常実行が終了しました");
  }
    //serialEncryption();
    //Serial.print("SerialEvent : ");
    //Serial.println(random_round10_create);
    //for(int i = 0;i < loop_count;i++){
      //random_round10_create++;
      //Serial.print("SerialEvent : ");
      //Serial.println(random_round10_create);
    //}
   Serial.println("SerialEventが終了しました");
   
}





/*****************************************************************************/

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  pinMode(PINNUM, OUTPUT);
  count = 0;
  carry = 0x00;
  data_count = 0;
  iterNum = 10;
  

}


void loop() {
  //Serial.println("シリアルモニタが起動されました");
  //Serial.print("");

  // put your main code here, to run repeatedly:
  if (Serial.available() > 0) {

    //serialreadで1を正しく読み込むため
    char serialread_char = Serial.read();
    int serialread = serialread_char - '0';

    //teshima = teshima - 0x30;
    
    Serial.println("loopが実行されました");
    
    switch (serialread) {
      
      case 1:
        Serial.println("case1が実行されました");
        
        serialEvent(1);
        
        Serial.println("case1が終了しました");
        Serial.end();
        break;
        
      default:
        Serial.println("defaultが実行されました");
        Serial.println("case1を正常に実行するためには1を入力してください");
        Serial.print("serialread : ");Serial.println(serialread);
        Serial.println("defaultが終了しました");
        //serialEvent();
        Serial.end();
        break;
    }
    Serial.println("loopが終了しました");//loopは終了しない
    //delay(1000);//2回の処理を避けるためにディレイを入れる
    

  }

}
