/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char path[100] = "/root/";
	int len=64;
	int cipherkey = 0;

	/* ---------- RSA ---------- */
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	/* ------------------------- */

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/* ---------- Encryption ---------- */
	if(strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "Ceaser") == 0) 
	// TEEencrypt –e [plaintext.txt] Ceaser
	{			
		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
						TEEC_VALUE_INOUT, //param for encrypted key
						TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		
		strcat(path, argv[2]);
		FILE *fp = fopen(path, "r"); // file open
		fgets(plaintext, sizeof(plaintext), fp); // copy plain text
		memcpy(op.params[0].tmpref.buffer, plaintext, len); 
		fclose(fp);

		printf("Plaintext : %s\n", plaintext);
		
		// TA encrypt service execute
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
			&err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
			&err_origin);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
			&err_origin);		

		char encrypted_path[100] = "/root/encrypt_"; // encrypted text file path
		strcat(encrypted_path, argv[2]); // file name: encrypt_(filename)
		FILE *fp_encrypted = fopen(encrypted_path, "w"); // file open with write
		memcpy(ciphertext, op.params[0].tmpref.buffer, len); // write to file		
		fputs(ciphertext, fp_encrypted);
		fclose(fp_encrypted); // close encrypted text file
		
		printf("Encrypted text : %s\n", ciphertext);

		char key_path[100] = "/root/key_"; // encrypted key file path
		strcat(key_path, argv[2]); // file name: key_(filename)
		FILE *fp_key = fopen(key_path, "w"); // file open with write
		cipherkey = op.params[1].value.a;
		fprintf(fp_key, "%d", cipherkey); // write key value to file
		fclose(fp_key);

		printf("Encrypted key : %d\n", cipherkey);
		
		printf("\nCeaser Encrypt complete.\n");

	}else if(strcmp(argv[1], "-d") == 0 && strcmp(argv[4], "Ceaser") == 0){	
		// TEEencrypt –d [ciphertext.txt][encryptedkey.txt] Ceaser
				
		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 
						TEEC_VALUE_INOUT, //param for encrypted key
						TEEC_NONE, TEEC_NONE);

		op.params[0].tmpref.buffer = plaintext;
		op.params[0].tmpref.size = len;
		
		strcat(path, argv[3]); // encrypted key file path
		FILE *fp_key = fopen(path, "r");
		fscanf(fp_key, "%d", &cipherkey); // read file
		op.params[1].value.a = cipherkey; // get encrypted key
		fclose(fp_key);
		
		printf("Encrypted key : %d\n", cipherkey);

		char path2[100] = "/root/";

		strcat(path2, argv[2]); // encrypted text file path
		FILE *fp = fopen(path2, "r");
		fgets(ciphertext, sizeof(ciphertext), fp); // read file		
		memcpy(op.params[0].tmpref.buffer, ciphertext, len); // get encrypted text
		fclose(fp);
	
		printf("Encrypted text : %s\n", ciphertext);	

		// TA decrypt service invoke
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);

		FILE *fp_decrypted = fopen("/root/decrypted.txt", "w"); // decrypted text file path
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		fputs(plaintext, fp_decrypted); // file write
		fclose(fp_decrypted);
		
		printf("Decrypted text : %s\n", plaintext);
		printf("Ceaser Decrypt complete.\n");

	}else if(strcmp(argv[1], "-e") == 0 && strcmp(argv[3], "RSA") == 0){
		// TEEencrypt –e [plaintext.txt] RSA 
		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = clear;
		op.params[0].tmpref.size = RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = ciph;
		op.params[1].tmpref.size = RSA_CIPHER_LEN_1024;
		
		strcat(path, argv[2]);
		FILE *fp = fopen(path, "r"); // file open
		fgets(clear, sizeof(clear), fp); // copy plain text
		fclose(fp);

		printf("Plaintext : %s\n", clear);

		// TA encrypt service invoke
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_GENKEYS) failed %#x\n", res);
	
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC,
				 &op, &err_origin);
		if (res != TEEC_SUCCESS)
				errx(1, "\nTEEC_InvokeCommand(TA_TEEencrypt_CMD_RSA_ENCRYPT) failed 0x%x origin 0x%x\n", res, err_origin);

		printf("Encrypted text : %s\n", ciph);

		char encrypted_path[100] = "/root/encrypt_RSA_"; // encrypted text file path
		strcat(encrypted_path, argv[2]);
		FILE *fp_encrypted = fopen(encrypted_path, "w");

		memcpy(ciph, op.params[1].tmpref.buffer, len); 

		fputs(ciph, fp_encrypted); // file write
		fclose(fp_encrypted);
		printf("RSA Encrypt complete.\n");

	}
	// RSA decrypt function is not implemented yet	
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
