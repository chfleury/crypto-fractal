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

// Função para criar a chave privada RSA a partir dos dois números fornecidos
RSA *createPrivateRSA(const char *n_str, const char *d_str)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    BN_dec2bn(&n, n_str);
    BN_dec2bn(&d, d_str);

    RSA_set0_key(rsa, n, NULL, d);

    return rsa;
}

// Função para descriptografar a imagem com RSA usando a chave privada de Bob
void decryptImageWithRSA(const char *privateKeyFile)
{
    printf("Inicia descriptografia\n");

    FILE *fp = fopen(privateKeyFile, "r");
    if (!fp)
    {
        perror("Erro ao abrir o arquivo da chave privada");
        return;
    }

    char n_str[256];
    char d_str[256];
    fscanf(fp, "%[^#]#%s", n_str, d_str);
    fclose(fp);

    RSA *rsa = createPrivateRSA(n_str, d_str);
    if (!rsa)
    {
        return;
    }

    // Abra o arquivo da imagem criptografada para leitura
    FILE *encryptedFile = fopen("fractal_encrypted.bmp", "rb");
    if (!encryptedFile)
    {
        perror("Erro ao abrir a imagem criptografada");
        RSA_free(rsa);
        return;
    }

    // Abra um novo arquivo para a imagem descriptografada
    FILE *decryptedFile = fopen("fractal_decrypted.bmp", "wb");
    if (!decryptedFile)
    {
        perror("Erro ao criar o arquivo para a imagem descriptografada");
        RSA_free(rsa);
        fclose(encryptedFile);
        return;
    }

    // Tamanho da chave privada em bytes
    int keySize = RSA_size(rsa);

    // Tamanho do bloco para descriptografar
    int blockSize = keySize;

    unsigned char *inBuffer = (unsigned char *)malloc(blockSize);
    unsigned char *outBuffer = (unsigned char *)malloc(keySize);

    int bytesRead;
    while ((bytesRead = fread(inBuffer, 1, blockSize, encryptedFile)) > 0)
    {
        int decryptedBytes = RSA_private_decrypt(bytesRead, inBuffer, outBuffer, rsa, RSA_PKCS1_PADDING);
        if (decryptedBytes < 0)
        {
            perror("Erro ao descriptografar a imagem");
            break;
        }
        fwrite(outBuffer, 1, decryptedBytes, decryptedFile);
    }

    free(inBuffer);
    free(outBuffer);

    RSA_free(rsa);
    fclose(encryptedFile);
    fclose(decryptedFile);

    printf("Imagem descriptografada com sucesso!\n");
}

int main()
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Criação do socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Erro ao criar o socket");
        return -1;
    }

    // Configuração do socket para permitir reuso do endereço
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("Erro na configuração do socket");
        return -1;
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Vincula o socket ao endereço e porta especificados
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("Falha na vinculação do socket");
        return -1;
    }

    // Inicia a escuta do socket, aguardando por conexões
    if (listen(server_fd, 3) < 0)
    {
        perror("Erro na escuta do socket");
        return -1;
    }

    // Aceita a conexão com Alice
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0)
    {
        perror("Erro na aceitação da conexão");
        return -1;
    }

    while (1)
    {
        // Recebe o tamanho da imagem criptografada de Alice
        long encryptedFileSize;
        if (recv(new_socket, &encryptedFileSize, sizeof(encryptedFileSize), 0) <= 0)
        {
            perror("Erro ao receber o tamanho da imagem");
            break;
        }

        // Recebe a imagem criptografada de Alice
        FILE *encryptedFile = fopen("fractal_encrypted.bmp", "wb");
        if (!encryptedFile)
        {
            perror("Erro ao criar o arquivo para a imagem criptografada");
            break;
        }

        size_t totalBytesReceived = 0;
        unsigned char buffer[BUFFER_SIZE];
        size_t bytesRead;
        while (totalBytesReceived < encryptedFileSize)
        {
            bytesRead = recv(new_socket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0)
            {
                perror("Erro ao receber a imagem criptografada");
                fclose(encryptedFile);
                remove("fractal_encrypted.bmp");
                break;
            }
            fwrite(buffer, 1, bytesRead, encryptedFile);
            totalBytesReceived += bytesRead;
        }

        fclose(encryptedFile);

        // Descriptografa a imagem criptografada recebida de Alice
        decryptImageWithRSA("../chave.priv");
    }

    close(new_socket);
    close(server_fd);

    return 0;
}
