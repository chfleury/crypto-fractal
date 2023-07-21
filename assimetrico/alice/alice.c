#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

// Função auxiliar para carregar uma chave pública RSA a partir de uma string no formato "n#e"
RSA *createRSA(const char *n_str, const char *e_str)
{
    printf("n: %s\n", n_str);
    printf("e: %s\n", e_str);

    RSA *rsa = RSA_new();
    if (!rsa)
    {
        printf("Erro ao criar estrutura RSA\n");
        return NULL;
    }

    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();

    if (!BN_hex2bn(&n, n_str))
    {
        printf("Erro ao converter 'n' para BIGNUM\n");
        RSA_free(rsa);
        return NULL;
    }

    if (!BN_hex2bn(&e, e_str))
    {
        printf("Erro ao converter 'e' para BIGNUM\n");
        BN_free(n);
        RSA_free(rsa);
        return NULL;
    }

    if (!RSA_set0_key(rsa, n, e, NULL))
    {
        printf("Erro ao configurar os componentes da chave pública RSA\n");
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return NULL;
    }

    return rsa;
}

// Função para criptografar a imagem com RSA usando a chave pública de Bob
void encryptImageWithRSA(const unsigned char *plain_text, int plain_text_len, const char *publicKeyFile)
{
    // Carrega a chave pública RSA de Bob a partir do arquivo "chave.pub"
    FILE *fp = fopen(publicKeyFile, "r");
    if (!fp)
    {
        perror("Erro ao abrir o arquivo da chave pública");
        exit(1);
    }

    char n_str[256];
    char e_str[256];

    fscanf(fp, "%[^#]#%s", n_str, e_str);
    fclose(fp);

    RSA *rsa = createRSA(n_str, e_str);
    if (!rsa)
    {
        printf("Erro ao criar a chave pública RSA\n");
        exit(1);
    }

    // Tamanho do bloco de criptografia (em bytes) usando a chave pública de Bob
    int rsa_block_size = RSA_size(rsa);
    printf("rsa_blocksize: %d\n", rsa_block_size);

    // Número de blocos necessários para criptografar todo o texto
    int num_blocks = (plain_text_len + rsa_block_size - 1) / rsa_block_size;
    printf("num_blocks: %d\n", num_blocks);

    // Tamanho total do texto criptografado (em bytes)
    int encrypted_text_len = rsa_block_size;
    printf("encrypted_text_len: %d\n", num_blocks);

    // Aloca memória para armazenar o texto criptografado
    unsigned char *encrypted_text = (unsigned char *)malloc(encrypted_text_len);
    if (!encrypted_text)
    {
        printf("Erro ao alocar memória para texto criptografado\n");
        RSA_free(rsa);
        exit(1);
    }

    // Criptografa o texto
    int result = RSA_public_encrypt(plain_text_len, plain_text, encrypted_text, rsa, RSA_PKCS1_PADDING);
    if (result == -1)
    {
        unsigned long err = ERR_get_error();
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        printf("Erro durante a criptografia: %s\n", err_msg);
        RSA_free(rsa);
        free(encrypted_text);
        exit(1);
    }

    // Copia o texto criptografado de volta para o buffer original
    memcpy((void *)plain_text, encrypted_text, encrypted_text_len);

    RSA_free(rsa);
    free(encrypted_text);
}

int main()
{
    OpenSSL_add_all_algorithms();
    // Configurações do socket
    int sockfd;
    struct sockaddr_in server_addr;

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

    printf("len do arquivo: %d\n", bmpSize);

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

    int encrypted_len = ((body_len + 7) / 8) * 8; // Round up to the nearest multiple of 8 bytes
    unsigned char *encrypted_fractal = (unsigned char *)malloc(encrypted_len);
    encryptImageWithRSA(buffer + 54, body_len, "../chave.pub");

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
