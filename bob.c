#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <unistd.h>
#include <arpa/inet.h>

// Função para realizar a descriptografia DES
void decrypt(const unsigned char *cipher_text, int cipher_text_len, const unsigned char *key, unsigned char *iv, unsigned char *plain_text)
{
    DES_cblock des_key;
    DES_key_schedule key_schedule;
    memcpy(des_key, key, 8);
    DES_set_odd_parity(&des_key);
    DES_set_key_checked(&des_key, &key_schedule);
    DES_ncbc_encrypt(cipher_text, plain_text, cipher_text_len, &key_schedule, iv, DES_DECRYPT);
}

int main()
{
    // Configurações do socket
    int sockfd, newsockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;
    char buffer[1078 + 1024]; // Tamanho máximo do cabeçalho (1078 bytes) + tamanho máximo do corpo criptografado (1024 bytes)

    // Chave simétrica para a descriptografia DES (8 bytes)
    unsigned char key[8];
    unsigned char iv[8];

    // Criação do socket TCP
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Erro ao criar o socket");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(8080); // Porta do servidor Bob (ajuste conforme necessário)
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Vinculação do socket à porta
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Erro ao vincular o socket à porta");
        exit(1);
    }

    // Habilita o socket a aguardar conexões
    listen(sockfd, 5);

    printf("Aguardando conexão...\n");

    // Aceita uma conexão entrante
    client_addr_len = sizeof(client_addr);
    newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (newsockfd < 0)
    {
        perror("Erro ao aceitar a conexão");
        exit(1);
    }

    printf("Conexão estabelecida com sucesso!\n");

    // Recebe a chave simétrica e o IV de Alice
    if (recv(newsockfd, key, sizeof(key), 0) < 0)
    {
        perror("Erro ao receber chave simétrica de Alice");
        exit(1);
    }

    if (recv(newsockfd, iv, sizeof(iv), 0) < 0)
    {
        perror("Erro ao receber IV de Alice");
        exit(1);
    }

    // Recebe o cabeçalho e o corpo criptografado do fractal de Alice
    int header_len = 54;
    int total_bytes_received = 0;
    int bytes_received;
    while (total_bytes_received < header_len)
    {
        bytes_received = recv(newsockfd, buffer + total_bytes_received, header_len - total_bytes_received, 0);
        if (bytes_received < 0)
        {
            perror("Erro ao receber cabeçalho de Alice");
            exit(1);
        }
        total_bytes_received += bytes_received;
    }

    int encrypted_len = 1024;
    total_bytes_received = 0;
    while (total_bytes_received < encrypted_len)
    {
        bytes_received = recv(newsockfd, buffer + header_len + total_bytes_received, encrypted_len - total_bytes_received, 0);
        if (bytes_received < 0)
        {
            perror("Erro ao receber corpo criptografado de Alice");
            exit(1);
        }
        total_bytes_received += bytes_received;
    }

    printf("Fractal criptografado recebido com sucesso!\n");

    // Realiza a descriptografia somente do corpo do fractal
    unsigned char *decrypted_fractal = (unsigned char *)malloc(encrypted_len);
    decrypt(buffer + header_len, encrypted_len, key, iv, decrypted_fractal);

    // Criação do arquivo BMP com o fractal criptografado
    FILE *fp_fractal_encrypted = fopen("fractalcriptografado.bmp", "wb");
    if (!fp_fractal_encrypted)
    {
        perror("Erro ao criar arquivo fractalcriptografado.bmp");
        exit(1);
    }
    fwrite(buffer, sizeof(unsigned char), header_len, fp_fractal_encrypted);
    fwrite(decrypted_fractal, sizeof(unsigned char), encrypted_len, fp_fractal_encrypted);
    fclose(fp_fractal_encrypted);

    // Recompõe o cabeçalho do BMP para o fractal descriptografado
    unsigned int width = *(unsigned int *)(buffer + 18);
    unsigned int height = *(unsigned int *)(buffer + 22);
    unsigned int image_size = width * height * 3; // O BMP está em RGB de 24 bits (3 bytes por pixel)
    unsigned int file_size = image_size + header_len;

    *(unsigned int *)(buffer + 2) = file_size;
    *(unsigned int *)(buffer + 34) = image_size;

    // Criação do arquivo BMP com o fractal descriptografado
    FILE *fp_fractal_decrypted = fopen("fractalplain.bmp", "wb");
    if (!fp_fractal_decrypted)
    {
        perror("Erro ao criar arquivo fractalplain.bmp");
        exit(1);
    }
    fwrite(buffer, sizeof(unsigned char), header_len, fp_fractal_decrypted);
    fwrite(decrypted_fractal, sizeof(unsigned char), encrypted_len, fp_fractal_decrypted);
    fclose(fp_fractal_decrypted);

    // Fechamento do socket e liberação da memória alocada
    close(newsockfd);
    close(sockfd);
    free(decrypted_fractal);

    return 0;
}
