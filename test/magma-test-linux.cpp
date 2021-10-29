#include <iostream>
#include "magma.h"
using namespace std;

Magma cipher;
void test_A_3_1();
void test_A_3_2();
void test_A_3_3();
void test_A_3_4();
void test_A_3_5();

int main()
{
    cipher.setKey({0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
                   0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff});
    test_A_3_1();
    test_A_3_2();
    test_A_3_3();
    test_A_3_4();
    test_A_3_5();
    return 0;
}

//A.3.1 transformation t
void test_A_3_1 () {
    uint32_t a = 0xfdb97531;
    cout << endl << "А.3.1 Преобразование t" << endl;
    for (int i=0; i<4; i++) {
        cout << "t(" << hex << a << ") = ";
        a = cipher.t(a);
        cout << hex << a << endl;
    }
}

//A.3.2 transformayion g
void test_A_3_2 () {
    cout << endl << "А.3.2 Преобразование g" << endl;
    uint32_t k = 0x87654321, a = 0xfedcba98;
    for (int i=0; i<4; i++) {
        cout << "g[" << hex << k << "](" << a << ") = ";
        a = cipher.g(k, a);
        cout << hex << a << endl;
        swap(k,a);
    }
}

//A.3.3 key shedule
void test_A_3_3 () {
    cout << endl << "А.3.3 Алгоритм развертывания ключа" << endl;
    cout << "Ключ имеет значение K = ";
    for (int i=0;i<8;i++) {
        cout << hex << cipher.key[i];
    }
    cout << endl << "Итерационные ключи Ki i=1,2..32 принимают следущие значения:" << endl;
    for (int i=0;i<32;i++) {
        cout << "K" << dec << i+1 << " = ";
        cout << hex << cipher.K[i] << endl;
    }
    cout << endl;
}

// encryption algorithm
void test_A_3_4 () {
    V32xV32 a ={0xfedcba98, 0x76543210};
    cout << endl << "А.3.4 Алгоритм зашифрования" << endl;
    cout << "(a1,a0)=(" << hex << a.a1 << "," << a.a0 << endl;

    for (int i=0;i<31;i++) {
        a = cipher.G(cipher.K[i], a);
        switch (i+1) {
        case 1:
            cout << "G[K1]";
            break;
        case 2:
            cout << "G[K2]G[K1]";
            break;
        default:
            cout << "G[K" + to_string(i+1) + "]..G[K1]";
            break;
        }
        cout << "(a1,a0) = " << "(" << hex << a.a1 << "," << a.a0 << ")" << endl;
    }
    cout << "Результатом зашифрования является шифртекст b=G*[K32]G[K31]..G[K1] = " << hex << cipher.G_(cipher.K[31], a) << endl;
}

// decryption algorithm
void test_A_3_5 () {
    V32xV32 b = {0x4ee901e5, 0xc2d8ca3d};
    cout << endl << "А.3.5 Алгоритм расшифрования" << endl;
    cout << "(b1,b0)=(" << hex << b.a1 << "," << b.a0 << endl;

    for (int i=31;i>0;i--) {
        b = cipher.G(cipher.K[i], b);
        switch (i+1) {
        case 32:
            cout << "G[K32]";
            break;
        case 31:
            cout << "G[K31]G[K32]";
            break;
        default:
            cout << "G[K" + to_string(i+1) + "]..G[K32]";
            break;
        }
        cout << "(b1,b0) = " << "(" << hex << b.a1 << "," << b.a0 << ")" << endl;
    }
    cout << "Результатом расшифрования является открытый текст a=G*[K1]G[K2]..G[K32] = " << hex << cipher.G_(cipher.K[0], b) << endl;
}
