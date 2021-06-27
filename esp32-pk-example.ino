#include <mbedtls/aes.h>
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
 

void setup() {
  Serial.begin(115200);
  Serial.println("Starting...");  
  
  // put your setup code here, to run once:
  RSA();
}

void loop() {
  // put your main code here, to run repeatedly:

}

// openssl genrsa -out 1.key 2048
// openssl rsa -pubout -in 1.key
const char *str_public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuuh3S4QlopYiU+All5rh\nCbhK+TfEtnND85mZ9d/CJDI2b+YN01OYopjQt+WH5UOnnXvwIq8OabHeUuBqRRva\n+mlVE5ZvVsTUuTVtzGbTYNaXLQ+oxUgNbBywOsvNefOu0PvxZrNTa+1E0XMVyu0e\nQhF8wD6+FghqB+eCF8YXH/z2h0PTndaOjSq4ZBBHVvU9tHXy9k60Ef0Z7V+6yjo+\nil00yobbcRnnYm6WpuYjV/JKgGKU5HkgNajTRmTC6xMlg1LQGZ58Bn/OLnKmOYbi\ndQekQRaQM1FScMYHx6Weon2wtTeBiLzdXIXWwjjv6ZoMFsdyhSsslHK3j1mGajLm\nMwIDAQAB\n-----END PUBLIC KEY-----";
const char *str_private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuuh3S4QlopYiU+All5rhCbhK+TfEtnND85mZ9d/CJDI2b+YN\n01OYopjQt+WH5UOnnXvwIq8OabHeUuBqRRva+mlVE5ZvVsTUuTVtzGbTYNaXLQ+o\nxUgNbBywOsvNefOu0PvxZrNTa+1E0XMVyu0eQhF8wD6+FghqB+eCF8YXH/z2h0PT\nndaOjSq4ZBBHVvU9tHXy9k60Ef0Z7V+6yjo+il00yobbcRnnYm6WpuYjV/JKgGKU\n5HkgNajTRmTC6xMlg1LQGZ58Bn/OLnKmOYbidQekQRaQM1FScMYHx6Weon2wtTeB\niLzdXIXWwjjv6ZoMFsdyhSsslHK3j1mGajLmMwIDAQABAoIBAHRkx8VzKayyKfZp\no39hp7pR1f6UyB+GcE6G3OXMzi2UR2ovrXRonqjC2VdrzNDs7LiZsdUnhqYzaeva\nbNNUoW1Hov9rszIpqP8dUp7zebbYa5RYKBWS5SjqRKSYvgCvy7HA83etPMn9G9oC\n/RM9zpX+Jd3iNKWr37vEY7NCXKxB3pGaTzIWdVAlelNSYXrUjpcmpVTPlM/jxs+H\nCC3r0F6HsiCwuG8PstG0q5+dUFNouaC95sOahDKYHkMUbV6y1cy7dX0Oh0njh7QH\nLagqSxUgwKBrvZ8+cROvhvt9zz8UM+Bb8UzrzcrbaLH0HbmLcB+WuMtzwWPbegyr\n15xdtkECgYEA6VkVmlWWQM1xNKmFygJon0qcIcqgMYCflfOHWac2pjcNyp+F4QMy\nqLtdHZVzg/SOzfCTIZCdpPqR3v2M4KbsSEFIM52Fwfp9SX7PRmULpagmETY15LXc\nc5nCjnV8jd91usFWTU+qqSQrIGR1JI9xxbd4047HX/CpHdh7w8iRXPkCgYEAzQ1O\naPoiMtxJEVxFXBpGqDnLYw0XJyp2/Z6t5x1rOuxc4l/6OMftgW9lMS5/MYL/Csqg\nNTf/qdE0gXMarCBFWKgTx9AmcvzP810fPIGoThdmxQpy4qu5KkycFWqEusVEgtVL\nmmL9nNTcwpOt961M7AB4vuoRHtBrGNkHIgzCg4sCgYBHLAG3ygUDDOZLbq082RE6\nDJKkh93mW1nRba7JvIOhnMcbFx7Ja6VG66bSACR0ieIIlCj8ItTCXh6hyenvF1qY\nCzlPbOtAJ/uQsBneWbF8vFWoCEXV1VZA+BPsSY9M4mxRIukEuZjO8BYrUhicpxfH\ne1diB3luHMQoM0BEjecwWQKBgQCawns2gesDxfyjzKdQr0g6uXwG4x9hYQxzuKp5\n71s6GqCz/kpFRqe79A5Ew1oeTUcepvWplP0x9wKQ3QX5eVW9ZwWe3jvWt3ZfsB3e\nNeGIJuNavdsdtwvGoBGBnGZW7IIb2M351NKi5olDleBMOZD/4g8/0DthrV3XYB2h\nFk5MpwKBgQCkG7tNHngrBYZuSOn+epGcPtQiFWdpKn98f7R0UZ0789SikPLkqVVk\n8zkJYm8BsP4Xr2lGkJ6U7kfrSuKX2FGbduP8bPWe75iffktVPKC9gq7RjvkRXhMg\nNaHVpqKPjOwBm+oCgQx3x7zb2u4qo+Yg1zkGHGsKhwnswQE7cT+39Q==\n-----END RSA PRIVATE KEY-----";

unsigned char encrypted[MBEDTLS_MPI_MAX_SIZE];
unsigned char decrypted[MBEDTLS_MPI_MAX_SIZE];

void RSA () {
    memset(encrypted, 0, sizeof(encrypted));
    memset(decrypted, 0, sizeof(decrypted));
    
    int ret = 0;
    mbedtls_pk_context cxt;
    mbedtls_pk_init(&cxt);
     
    if (ret = mbedtls_pk_parse_public_key(&cxt, (unsigned char*)str_public_key, strlen(str_public_key)+1)  != 0) {
      Serial.printf("Pub key load failed! ...\n");
      return;
    } 
    
    Serial.printf("Pub key loaded...\n");    
        
    size_t olen = 0;
    unsigned char to_encrypt[] = "This is a test..This is a test..This is a test..";
    size_t to_encrypt_len = sizeof(to_encrypt);

    if( to_encrypt_len > 100 ) {
        Serial.printf("Input data larger than 100 characters.\n\n" );
        return;
    }
    
    mbedtls_ctr_drbg_context ctr_drbg;
    char *personalization = "personalization";
    
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy,
                     (const unsigned char *) personalization,
                     strlen( personalization ) );

    if( ( ret = mbedtls_pk_encrypt( &cxt, to_encrypt, to_encrypt_len,
                                    encrypted, &olen, sizeof(encrypted),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        Serial.printf("failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n", -ret );
        return;
    }
    
    Serial.printf("Encrypted...");
    Serial.printf("done. Size: %i \n", sizeof(encrypted));
        
//    int i;
//    for(i = 0; i < 256; i++ ) {
//       Serial.printf( "%02x[%c]%c", encrypted[i], (encrypted[i]>31)?encrypted[i]:' ', ((i&0xf)!=0xf)?' ':'\n' );
//    }
//    
//    Serial.printf( "\n" );

    
    //Decrypt

    mbedtls_pk_init( &cxt );

    if ( ret = mbedtls_pk_parse_key(&cxt, (unsigned char*)str_private_key, strlen(str_private_key) +1, NULL, NULL)  != 0 ) {
      Serial.printf("Private key load failed!...\n");
      return;
    }

    Serial.printf("Priv Key loaded...\n");
        
//    Serial.printf( "Decrypting...\n" );
//    Serial.printf("encrypted: %i \n", sizeof(encrypted));
//    Serial.printf("Olen: %i \n", olen);
//    Serial.printf("Decrypted: %i \n", sizeof(decrypted));
//    Serial.printf("1024: %i \n", 1024);
    
    if( ( ret = mbedtls_pk_decrypt( &cxt, encrypted, olen, decrypted, &olen, sizeof(decrypted),
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        Serial.printf( " failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", -ret );
        return; 
    }
    
    Serial.printf("Decrypted...\n");    
    Serial.printf("Decrypted Text: %s \n", decrypted);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );    
    mbedtls_pk_free(&cxt);

//    for( i = 0; i < 128; i++ ) {
//        Serial.printf( "%02x[%c]%c", decrypted[i], (decrypted[i]>31)?decrypted[i]:' ', ((i&0xf)!=0xf)?' ':'\n' );
//    }    
//    Serial.printf( "\n" );    

}
 
 // Based on   
 // https://cpp.hotexamples.com/examples/-/-/mbedtls_pk_encrypt/cpp-mbedtls_pk_encrypt-function-examples.html
