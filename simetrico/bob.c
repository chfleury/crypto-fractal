#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/des.h>
#include <openssl/rand.h>

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
    OpenSSL_add_all_algorithms();
    // Configurações do socket
    int sockfd, newsockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len;

    // Chave simétrica e IV para a descriptografia DES (8 bytes cada)
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

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Erro ao fazer bind");
        exit(1);
    }

    if (listen(sockfd, 1) < 0)
    {
        perror("Erro ao ouvir");
        exit(1);
    }

    printf("Aguardando conexão de Alice...\n");
    client_addr_len = sizeof(client_addr);
    newsockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (newsockfd < 0)
    {
        perror("Erro ao aceitar a conexão");
        exit(1);
    }

    printf("Conexão estabelecida com Alice.\n");

    // Recebe a chave simétrica enviada por Alice
    int key_size = 8;
    if (recv(newsockfd, key, key_size, 0) < 0)
    {
        perror("Erro ao receber a chave simétrica de Alice");
        close(newsockfd); // Fecha o novo socket criado para a conexão com Alice
        close(sockfd);
        exit(1);
    }

    // Recebe o IV enviado por Alice
    int iv_size = 8;
    if (recv(newsockfd, iv, iv_size, 0) < 0)
    {
        perror("Erro ao receber o IV de Alice");
        close(newsockfd); // Fecha o novo socket criado para a conexão com Alice
        close(sockfd);
        exit(1);
    }

    int encrypted_body_len;

    if (recv(newsockfd, &encrypted_body_len, sizeof(int), 0) < 0)
    {
        perror("Erro ao receber o encrypted_body_len de Alice");
        close(newsockfd); // Fecha o novo socket criado para a conexão com Alice
        close(sockfd);
        exit(1);
    }

    printf("len do encrypted_body_len%d\n", encrypted_body_len);

    // Tamanho total do cabeçalho e corpo criptografado

    // Recebe o cabeçalho e o corpo criptografado do fractal em uma única mensagem
    unsigned char *received_data = (unsigned char *)malloc(encrypted_body_len + 54);
    // int bytes_received = recv(newsockfd, received_data, encrypted_body_len + 54, 0);

    int total_received = 0;
    int remaining = encrypted_body_len + 54;

    while (remaining > 0)
    {
        int bytes_received = recv(newsockfd, received_data + total_received, remaining, 0);
        if (bytes_received <= 0)
        {
            perror("Erro ao receber o fractal criptografado de Alice");
            free(received_data);
            close(newsockfd);
            close(sockfd);
            exit(1);
        }

        total_received += bytes_received;
        remaining -= bytes_received;
    }

    printf("len do bytes_received%d\n", total_received);

    if (total_received < 0)
    {
        perror("Erro ao receber o fractal criptografado de Alice");
        free(received_data);
        close(newsockfd);
        close(sockfd);
        exit(1);
    }

    FILE *fp_fractal_riptografado = fopen("fractalcriptograma.bmp", "wb");
    fwrite(received_data, sizeof(unsigned char), total_received, fp_fractal_riptografado);
    fclose(fp_fractal_riptografado);

    printf("Imagem salva: fractalcriptograma.bmp\n");

    // Separa o cabeçalho do corpo criptografado
    unsigned char *header = (unsigned char *)malloc(54);
    unsigned char *encrypted_fractal = (unsigned char *)malloc(encrypted_body_len);

    memcpy(header, received_data, 54);
    memcpy(encrypted_fractal, received_data + 54, encrypted_body_len);
    printf("len %d", encrypted_body_len);

    printf("imagezie %d!\n");
    // Realiza a descriptografia somente do corpo do fractal
    unsigned char *decrypted_fractal = (unsigned char *)malloc(encrypted_body_len);
    decrypt(encrypted_fractal, encrypted_body_len, key, iv, decrypted_fractal);

    // Criação do arquivo fractalplain.bmp com o conteúdo descriptografado
    FILE *fp_fractal_descriptografado = fopen("fractalplain.bmp", "wb");
    fwrite(header, sizeof(unsigned char), 54, fp_fractal_descriptografado);
    fwrite(decrypted_fractal, sizeof(unsigned char), encrypted_body_len, fp_fractal_descriptografado);
    fclose(fp_fractal_descriptografado);

    printf("Imagem salva: fractalplain.bmp\n");

    // Fechamento do socket e liberação da memória alocada
    close(newsockfd);
    close(sockfd);
    free(header);
    free(encrypted_fractal);
    free(decrypted_fractal);
    free(received_data);

    return 0;
}
