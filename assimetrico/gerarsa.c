#include <stdio.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define NUM_DIGITS_MIN 10000
#define NUM_DIGITS_MAX 999999

int generate_primes(BIGNUM **p, BIGNUM **q)
{
    BIGNUM *start = BN_new();
    BIGNUM *end = BN_new();
    BN_set_word(start, NUM_DIGITS_MIN);
    BN_set_word(end, NUM_DIGITS_MAX);

    BIGNUM *tmp_p = BN_new();
    BIGNUM *tmp_q = BN_new();

    int success = 0;
    int attempts = 0;
    int max_attempts = 10000; // Maximum number of attempts to generate primes

    while (!success && attempts < max_attempts)
    {
        BN_rand_range(tmp_p, end);
        BN_add(tmp_p, tmp_p, start);
        BN_generate_prime_ex(tmp_p, 2048, 0, NULL, NULL, NULL);

        BN_rand_range(tmp_q, end);
        BN_add(tmp_q, tmp_q, start);
        BN_generate_prime_ex(tmp_q, 2048, 0, NULL, NULL, NULL);

        // Check if p and q are different primes
        if (BN_cmp(tmp_p, tmp_q) != 0)
        {
            *p = tmp_p;
            *q = tmp_q;
            success = 1;
        }
        else
        {
            BN_clear_free(tmp_p);
            BN_clear_free(tmp_q);
        }

        attempts++;
    }

    BN_free(start);
    BN_free(end);
    return success;
}

int main(int argc, char *argv[])
{
    if (argc != 2 || argv[1][0] != '-')
    {
        printf("Uso: %s -p\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-p") != 0)
    {
        printf("Opção inválida. Use: %s -p\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();

    BIGNUM *p = NULL;
    BIGNUM *q = NULL;

    if (generate_primes(&p, &q))
    {
        FILE *output_file = fopen("primos.txt", "w");
        if (!output_file)
        {
            printf("Erro ao abrir o arquivo para escrita.\n");
            return 1;
        }

        // Escrever os primos no arquivo
        BN_print_fp(output_file, p);
        fprintf(output_file, "#");
        BN_print_fp(output_file, q);

        fclose(output_file);

        // Gerar chaves pública e privada
        RSA *rsa = RSA_new();
        BIGNUM *e = BN_new();
        BN_set_word(e, RSA_F4); // RSA_F4 é o expoente público comum

        RSA_generate_key_ex(rsa, 2048, e, NULL); // Gerar chaves de 2048 bits

        // Configurar p e q no objeto RSA
        if (!RSA_set0_factors(rsa, p, q))
        {
            printf("Erro ao configurar os números primos no objeto RSA.\n");
            return 1;
        }

        FILE *pub_key_file = fopen("chave.pub", "w");
        FILE *priv_key_file = fopen("chave.priv", "w");

        if (!pub_key_file || !priv_key_file)
        {
            printf("Erro ao abrir os arquivos das chaves.\n");
            return 1;
        }

        PEM_write_RSAPublicKey(pub_key_file, rsa);
        PEM_write_RSAPrivateKey(priv_key_file, rsa, NULL, NULL, 0, NULL, NULL);

        fclose(pub_key_file);
        fclose(priv_key_file);

        RSA_free(rsa);
        BN_free(e);
    }
    else
    {
        printf("Não foi possível gerar os números primos. Tente novamente.\n");
        return 1;
    }

    // Liberação da memória alocada para p e q
    if (p)
        BN_free(p);
    if (q)
        BN_free(q);

    return 0;
}
