#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include <arpa/inet.h>

// Função para realizar a criptografia DES
void encrypt(const unsigned char *plain_text, int plain_text_len, const unsigned char *key, unsigned char *iv, unsigned char *cipher_text)
{
    DES_cblock des_key;
    DES_key_schedule key_schedule;
    memcpy(des_key, key, 8);
    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &key_schedule);
    DES_ncbc_encrypt(plain_text, cipher_text, plain_text_len, &key_schedule, iv, DES_ENCRYPT);
}

int main()
{
    OpenSSL_add_all_algorithms();
    // Configurações do socket
    int sockfd;
    struct sockaddr_in server_addr;

    // Chave simétrica para a criptografia DES (8 bytes)
    unsigned char key[8];
    RAND_bytes(key, sizeof(key));

    // IV para a criptografia DES (8 bytes)
    unsigned char iv[8];
    RAND_bytes(iv, sizeof(iv));

    // Leitura do fractal a partir do arquivo BMP
    FILE *fp_fractal = fopen("fractaljulia.bmp", "rb");
    if (!fp_fractal)
    {
        perror("Erro ao abrir o arquivo fractaljulia.bmp");
        exit(1);
    }

    fseek(fp_fractal, 0, SEEK_END);
    int bmpSize = ftell(fp_fractal);
    fseek(fp_fractal, 0, SEEK_SET);

    printf("len do arquivo%d\n", bmpSize);

    unsigned char *buffer = (unsigned char *)malloc(bmpSize);
    fread(buffer, 1, bmpSize, fp_fractal);
    fclose(fp_fractal);

    // Copy the first 54 bytes to the 'header' variable
    unsigned char *header = (unsigned char *)malloc(54);

    int imagesize;

    memcpy(&imagesize, buffer + 34, sizeof(int));

    memcpy(header, buffer, 54);

    // Calculate the size of the 'body' variable
    int body_len = bmpSize - 54;

    // Allocate memory for the 'body' variable
    // unsigned char *body = (unsigned char *)malloc(body_len);

    // Copy the rest of the data (after the header) to the 'body' variable
    // memcpy(body, buffer + 54, body_len);

    // Criptografa o corpo do arquivo BMP
    int encrypted_len = ((body_len + 7) / 8) * 8; // Round up to the nearest multiple of 8 bytes
    unsigned char *encrypted_fractal = (unsigned char *)malloc(encrypted_len);
    encrypt(buffer + 54, body_len, key, iv, encrypted_fractal);

    printf("len %d", encrypted_len);

    // Combina o cabeçalho com o corpo criptografado
    unsigned char *full_fractal = (unsigned char *)malloc(54 + encrypted_len);
    memcpy(full_fractal, header, 54);
    memcpy(full_fractal + 54, encrypted_fractal, encrypted_len);

    // Criação do socket TCP
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Erro ao criar o socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080);                   // Porta do servidor Bob (ajuste conforme necessário)
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // IP do servidor Bob (ajuste conforme necessário)

    // Conexão ao servidor
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Erro ao conectar ao servidor");
        exit(1);
    }

    // Envia a chave simétrica e o IV para o servidor Bob
    if (send(sockfd, key, sizeof(key), 0) < 0)
    {
        perror("Erro ao enviar chave simétrica para o servidor");
        exit(1);
    }

    if (send(sockfd, iv, sizeof(iv), 0) < 0)
    {
        perror("Erro ao enviar IV para o servidor");
        exit(1);
    }

    if (send(sockfd, &encrypted_len, sizeof(encrypted_len), 0) < 0)
    {
        perror("Erro ao enviar encrypted_len para o servidor");
        exit(1);
    }

    printf("len do encrypted_len%d\n", encrypted_len);

    if (send(sockfd, full_fractal, encrypted_len + 54, 0) < 0)
    {
        perror("Erro ao enviar fractal criptografado para o servidor");
        exit(1);
    }

    FILE *fp_fractal_decrypted = fopen("alo.bmp", "wb");
    if (!fp_fractal_decrypted)
    {
        perror("Erro ao criar arquivo fractalplain.bmp");
        exit(1);
    }

    fwrite(full_fractal, sizeof(unsigned char), encrypted_len + 54, fp_fractal_decrypted);
    fclose(fp_fractal_decrypted);

    close(sockfd);
    free(encrypted_fractal);
    free(full_fractal);

    free(header);
    // free(body);
    free(buffer);

    return 0;
}
