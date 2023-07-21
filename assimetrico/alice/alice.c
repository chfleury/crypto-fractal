#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Função para criar a chave pública RSA a partir dos dois números fornecidos
RSA *createRSA(const char *n_str, const char *e_str)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();

    BN_dec2bn(&n, n_str);
    BN_dec2bn(&e, e_str);

    RSA_set0_key(rsa, n, e, NULL);

    return rsa;
}

// Função para criptografar a imagem com RSA usando a chave pública de Bob
void encryptImageWithRSA(const char *publicKeyFile)
{
    FILE *fp = fopen(publicKeyFile, "r");
    if (!fp)
    {
        perror("Erro ao abrir o arquivo da chave pública");
        return;
    }

    char n_str[256];
    char e_str[256];
    fscanf(fp, "%[^#]#%s", n_str, e_str);
    fclose(fp);

        RSA *rsa = createRSA(n_str, e_str);

    if (!rsa)
    {
        return;
    }

    // Abra o arquivo da imagem para leitura
    FILE *img_fp = fopen("fractal.bmp", "rb");
    if (!img_fp)
    {
        perror("Erro ao abrir a imagem fractal.bmp");
        RSA_free(rsa);
        return;
    }

    // Verifique o tamanho do arquivo da imagem
    fseek(img_fp, 0, SEEK_END);
    long fileSize = ftell(img_fp);
    fseek(img_fp, 0, SEEK_SET);

    if (fileSize == 0)
    {
        perror("Arquivo de imagem vazio");
        fclose(img_fp);
        return;
    }

    // Abra um novo arquivo para a imagem criptografada
    FILE *encryptedFile = fopen("fractal_encrypted.bmp", "wb");
    if (!encryptedFile)
    {
        perror("Erro ao criar o arquivo para a imagem criptografada");
        RSA_free(rsa);
        fclose(img_fp);
        return;
    }

    // Tamanho da chave pública em bytes
    int keySize = RSA_size(rsa);

    unsigned char *inBuffer = (unsigned char *)malloc(fileSize);
    unsigned char *outBuffer = (unsigned char *)malloc(keySize + 1);

    int bytesRead;
    while ((bytesRead = fread(inBuffer, 1, fileSize, img_fp)) > 0)
    {
        int encryptedBytes = RSA_public_encrypt(bytesRead, inBuffer, outBuffer, rsa, RSA_PKCS1_PADDING);
        printf("%d\n\n", encryptedBytes);
        if (encryptedBytes <= 0)
        {
            perror("Erro ao criptografar a imagem");
            RSA_free(rsa);
            fclose(img_fp);
            fclose(encryptedFile);
            return;
        }

        fwrite(outBuffer, 1, encryptedBytes, encryptedFile);
    }

    free(inBuffer);
    free(outBuffer);

    RSA_free(rsa);
    fclose(img_fp);
    fclose(encryptedFile);

    printf("Imagem criptografada com sucesso!\n");
}

int sendData(int sock, const void *data, size_t size)
{
    size_t totalSent = 0;
    while (totalSent < size)
    {
        int bytesSent = send(sock, (const char *)data + totalSent, size - totalSent, 0);
        if (bytesSent < 0)
        {
            perror("Erro ao enviar dados");
            return -1;
        }
        totalSent += bytesSent;
    }
    return 0;
}

void sendEncryptedImageToBob(const char *encryptedImageFile, int sock)
{
    FILE *encryptedFile = fopen(encryptedImageFile, "rb");
    if (!encryptedFile)
    {
        perror("Erro ao abrir a imagem criptografada");
        return;
    }

    // Obtenha o tamanho da imagem criptografada
    fseek(encryptedFile, 0, SEEK_END);
    long encryptedFileSize = ftell(encryptedFile);
    fseek(encryptedFile, 0, SEEK_SET);

    // Envie o tamanho da imagem para Bob
    if (sendData(sock, &encryptedFileSize, sizeof(encryptedFileSize)) < 0)
    {
        fclose(encryptedFile);
        return;
    }

    // Envie a imagem criptografada para Bob
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), encryptedFile)) > 0)
    {
        if (sendData(sock, buffer, bytesRead) < 0)
        {
            fclose(encryptedFile);
            return;
        }
    }

    fclose(encryptedFile);

    printf("Imagem criptografada enviada para Bob com sucesso!\n");
}

int main()
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    printf("Digite uma mensagem para enviar (ou --send-encrypted-fractal para criptografar e enviar a imagem)\n\n");

    // Criação do socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\nErro ao criar o socket\n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Converte o endereço IP de texto para binário
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        printf("\nEndereço inválido/sem suporte\n");
        return -1;
    }

    // Conecta-se ao servidor (Bob)
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConexão Falhou\n");
        return -1;
    }

    while (1)
    {
        // Recebe o comando do usuário
        printf("Alice: ");
        fgets(buffer, BUFFER_SIZE, stdin);

        if (strcmp(buffer, "--send-encrypted-fractal\n") == 0)
        {
            // Criptografa e envia a imagem
            encryptImageWithRSA("../chave.pub");

            // Depois de criptografar a imagem, envia-a para Bob usando a conexão TCP existente.
            sendEncryptedImageToBob("fractal_encrypted.bmp", sock);
        }
        else
        {
            // Envia a mensagem normalmente
            send(sock, buffer, strlen(buffer), 0);
        }
    }

    close(sock);

    return 0;
}
