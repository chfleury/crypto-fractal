#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <math.h>

// Função para verificar se um número é primo
bool is_prime(int num)
{
    if (num <= 1)
        return false;
    if (num <= 3)
        return true;

    if (num % 2 == 0 || num % 3 == 0)
        return false;

    for (int i = 5; i * i <= num; i += 6)
    {
        if (num % i == 0 || num % (i + 2) == 0)
            return false;
    }

    return true;
}

// Função para gerar números primos com cinco a seis dígitos
int generate_prime()
{
    int num;
    do
    {
        num = rand() % 99999 + 10000;
    } while (!is_prime(num));

    return num;
}

// Função para calcular o máximo divisor comum (MDC) de dois números
int gcd(int a, int b)
{
    if (b == 0)
        return a;
    return gcd(b, a % b);
}

// Função para calcular o inverso multiplicativo usando o algoritmo estendido de Euclides
int mod_inverse(int a, int m)
{
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    while (a > 1)
    {
        // q é o quociente da divisão de a por m
        q = a / m;

        t = m;

        // m é o resto da divisão de a por m
        m = a % m;
        a = t;

        t = x0;

        // atualiza x0 e x1 usando o algoritmo de Euclides estendido
        x0 = x1 - q * x0;
        x1 = t;
    }

    // Certifica-se de que x1 é positivo
    if (x1 < 0)
        x1 += m0;

    return x1;
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    int p, q;

    // Verifica se o usuário passou o parâmetro -p
    if (argc == 2 && strcmp(argv[1], "-p") == 0)
    {
        p = generate_prime();
        q = generate_prime();

        // Salva os números primos p e q no arquivo primos.txt
        FILE *primes_file = fopen("primos.txt", "w");
        if (primes_file == NULL)
        {
            printf("Erro ao criar o arquivo primos.txt.\n");
            return 1;
        }
        fprintf(primes_file, "%d#%d", p, q);
        fclose(primes_file);

        printf("Números primos gerados e salvos em primos.txt: %d e %d\n", p, q);
    }
    else
    {
        // Lê os números primos p e q do arquivo primos.txt
        FILE *primes_file = fopen("primos.txt", "r");
        if (primes_file == NULL)
        {
            printf("Erro ao abrir o arquivo primos.txt.\n");
            return 1;
        }

        fscanf(primes_file, "%d#%d", &p, &q);
        fclose(primes_file);
    }

    // Calcula o valor de n e phi(n)
    int n = p * q;
    int phi_n = (p - 1) * (q - 1);

    // Escolhe um valor para e (o valor de e deve ser relativamente primo a phi(n))
    int e;
    do
    {
        e = rand() % phi_n;
    } while (gcd(e, phi_n) != 1);

    // Calcula o valor de d (inverso multiplicativo de e módulo phi(n))
    int d = mod_inverse(e, phi_n);

    // Salva a chave pública no arquivo chave.pub
    FILE *pub_file = fopen("chave.pub", "w");
    if (pub_file == NULL)
    {
        printf("Erro ao criar o arquivo chave.pub.\n");
        return 1;
    }
    fprintf(pub_file, "%d#%d", n, e);
    fclose(pub_file);

    // Salva a chave privada no arquivo chave.priv
    FILE *priv_file = fopen("chave.priv", "w");
    if (priv_file == NULL)
    {
        printf("Erro ao criar o arquivo chave.priv.\n");
        return 1;
    }
    fprintf(priv_file, "%d#%d", n, d);
    fclose(priv_file);

    printf("Chaves pública e privada geradas e salvas nos arquivos chave.pub e chave.priv.\n");

    return 0;
}
