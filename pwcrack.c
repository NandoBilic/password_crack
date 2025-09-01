#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include <stdlib.h>

uint8_t hex_to_byte(unsigned char h1, unsigned char h2);
void hexstr_to_hash(char hexstr[], unsigned char hash[32]);
int8_t check_password(char password[],unsigned char given_hash[32]);
int8_t crack_password(char password[], unsigned char given_hash[]);

void test_hex_to_byte() {

	assert(hex_to_byte('c', '8') == 200);
	assert(hex_to_byte('0', '3') == 3);
	assert(hex_to_byte('0', 'a') == 10);
	assert(hex_to_byte('1', '0') == 16);
}

void test_hexstr_to_hash() {
  char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
  unsigned char hash[32];
  hexstr_to_hash(hexstr, hash);
  int i;
  for( i = 0; i < 32; i += 1) {
 	printf(" %hhx  ",hash[i]);
  }
  assert(hash[0] == 0xa2);
  assert(hash[31] == 0xfd);
}

void test_check_password() {
	char hash_as_hexstr[64] ="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
	unsigned char given_hash[32];
	hexstr_to_hash(hash_as_hexstr,given_hash);
	assert(check_password("password", given_hash) == 1);
	assert(check_password("wrongpass", given_hash) == 0);


}

const int SHA_LENGTH = 32;
const int testing =0 ;
int main(int argc, char** argv) {
	if(testing) {
   		 test_hex_to_byte();
   		 test_hexstr_to_hash();
   		 test_check_password();
	}
	else{
		unsigned char password_hash[32];
		char password_string[200];
		char password[200];
		hexstr_to_hash(argv[1],password_hash);
		//printf("Password\n");
		//printf("NeverGuessMe!!\n");

		while (fgets(password_string,200,stdin)){
			if (password_string[strlen(password_string) -1] == '\n'){
				int i;
				for(i = 0; i < strlen(password_string) - 1; i++) {
					password[i] = password_string[i];
				}
				password[i] = '\0';
			}
			else{
				int i;
				for(i = 0; i < strlen(password_string); i++){
					password[i] = password_string[i];
				}
				password[i] = '\0';		
			}
			uint8_t bol = crack_password(password,password_hash);
			if(bol == 1) {
				printf("Found password: SHA256(%s) = %s\n",password,argv[1]);
				return 0;
			}
		}
		printf("Did not find a matching password\n");
	}
	return 0;
}



uint8_t hex_to_byte(unsigned char h1, unsigned char h2){
	uint8_t v1;
    	uint8_t v2;
		
	if (h1 >= 'a' && h1 <= 'f') {
		v1 = h1 - 87;
	}
	if (h1 >= '0' && h1 <= '9'){
		v1 = h1 - 48;
	}
	
	if (h2 >= 'a' && h2 <= 'f') {
		v2 = h2 -87;
	}
	if(h2 >= '0' && h2 <= '9') {
		v2 = h2 - 48;
	}
	
	return ((v1 * 16 ) + v2);
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]){
	int i;
	for(i = 0 ; i < strlen(hexstr) ; i += 2) {
		hash[i/2] = hex_to_byte(hexstr[i],hexstr[i + 1]);
	}
	hash[i/2] = '\0';
}

int8_t check_password(char password[],unsigned char given_hash[32]){
	unsigned char hash[SHA_LENGTH];
	SHA256(password,strlen(password),hash);
	int i;
	for(i = 0 ; i < 32 ; i++) {
		if(given_hash[i] != hash[i]){
			return 0;
		}
	}
	return 1;

}	


int8_t crack_password(char password[], unsigned char given_hash[]){
	uint8_t len = strlen(password);
	if(check_password(password,given_hash)){
		return 1;
	}
	int i;
	for(i = 0 ; i < len ; i++){
		if(password[i] >= 'a' && password[i] <= 'z'){
			char original = password[i];
			password[i] = original  - 32;
			if(check_password(password,given_hash)){
				return 1;
			}
			password[i] = original;
		}
		else if(password[i] >= 'A' && password[i] <= 'Z'){
			char original = password[i];
			password[i] = original + 32;
			if(check_password(password,given_hash)){
				return 1;
			}
			password[i] = original;
		}
		else if (password[i] >= '0' && password[i] <= '9') {
			char original = password[i];
			for(int j = 0; j <= 9 ; j++ ) {
				password[i] = '0' + j;
				if (check_password(password,given_hash)){
					return 1;
				}
			}
			password[i] = original;

		}
	}
	return 0;
}

