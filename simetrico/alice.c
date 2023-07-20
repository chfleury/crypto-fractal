#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <unistd.h>
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
    // Configurações do socket
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1078 + 1024]; // Tamanho máximo do cabeçalho (1078 bytes) + tamanho máximo do corpo criptografado (1024 bytes)

    // Chave simétrica para a criptografia DES (8 bytes)
    unsigned char key[8] = "secret_k"; // Chave de exemplo (ajuste conforme necessário)
    unsigned char iv[8] = "iv_data";   // IV de exemplo (ajuste conforme necessário)

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
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0)
    {
        perror("Endereço de IP inválido ou não suportado");
        exit(1);
    }

    // Conexão ao servidor Bob
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Erro ao conectar-se ao servidor");
        exit(1);
    }

    printf("Conexão estabelecida com o servidor!\n");

    // Leitura do arquivo BMP
    FILE *fp_fractal = fopen("fractal.bmp", "rb");
    if (!fp_fractal)
    {
        perror("Erro ao abrir o arquivo fractal.bmp");
        exit(1);
    }

    // Obter o tamanho do arquivo BMP
    fseek(fp_fractal, 0, SEEK_END);
    long bmp_file_size = ftell(fp_fractal);
    fseek(fp_fractal, 0, SEEK_SET);

    // Lê o cabeçalho BMP do arquivo
    if (fread(buffer, sizeof(unsigned char), 1078, fp_fractal) != 1078)
    {
        perror("Erro ao ler o cabeçalho BMP");
        fclose(fp_fractal);
        exit(1);
    }

    // Lê o corpo do arquivo BMP e criptografa
    int body_len = bmp_file_size - 1078;
    unsigned char *bmp_body = (unsigned char *)malloc(body_len);
    if (fread(bmp_body, sizeof(unsigned char), body_len, fp_fractal) != body_len)
    {
        perror("Erro ao ler o corpo do BMP");
        fclose(fp_fractal);
        free(bmp_body);
        exit(1);
    }
    fclose(fp_fractal);

    // Criptografa o corpo do BMP
    unsigned char *encrypted_bmp_body = (unsigned char *)malloc(body_len);
    encrypt(bmp_body, body_len, key, iv, encrypted_bmp_body);

    // Envia o tamanho total (cabeçalho + corpo criptografado) para o servidor
    int total_size = 1078 + body_len;
    if (send(sockfd, &total_size, sizeof(total_size), 0) == -1)
    {
        perror("Erro ao enviar o tamanho total para o servidor");
        free(bmp_body);
        free(encrypted_bmp_body);
        close(sockfd);
        exit(1);
    }

    // Envia o cabeçalho e o corpo criptografado em uma única mensagem
    memcpy(buffer + 1078, encrypted_bmp_body, body_len);
    if (send(sockfd, buffer, total_size, 0) == -1)
    {
        perror("Erro ao enviar o fractal criptografado para o servidor");
        free(bmp_body);
        free(encrypted_bmp_body);
        close(sockfd);
        exit(1);
    }

    printf("Fractal criptografado enviado para o servidor!\n");

    // Libera a memória alocada
    free(bmp_body);
    free(encrypted_bmp_body);
    close(sockfd);

    return 0;
}
