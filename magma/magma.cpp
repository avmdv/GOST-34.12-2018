#include "magma.h"
#include <iostream>
using namespace std;

//rl11:V32->V32   rl11(a)=a<<<11
uint32_t Magma::rl11 (uint32_t a) {
    return (a << 11) | (a >> 21);
}

// t:V32->V32   t(a)=t(a7|...|a0)=π7(a7)...π0(a0)
uint32_t Magma::t(uint32_t a) {
    return (pi[7][(a >> 28) & 0xf] << 28) | (pi[6][(a >> 24) & 0xf] << 24) |
           (pi[5][(a >> 20) & 0xf] << 20) | (pi[4][(a >> 16) & 0xf] << 16) |
           (pi[3][(a >> 12) & 0xf] << 12) | (pi[2][(a >> 8) & 0xf] << 8) |
           (pi[1][(a >> 4) & 0xf] << 4) | pi[0][a & 0xf];
}

// g[k]:V32->V32   g[k](a)=t(Vec32(Int32(a)⊞Int32(k)))<<<11
uint32_t Magma::g(uint32_t k, uint32_t a) {
    return rl11(t(a + k));
}

//G[K]:V32xV32->V32xV32   G[K](a1,a0)=(a0,g[k](a0)⊕a1)
V32xV32 Magma::G(uint32_t k, V32xV32 a) {
    return {a.a0, g(k, a.a0) ^ a.a1};
}

//G_[K]:V32xV32->V64   G_[K](a1,a0)=(g[k](a0)⊕a1)|a0
uint64_t Magma::G_(uint32_t k, V32xV32 a) {
    return (((uint64_t) (g(k, a.a0) ^ a.a1) << 32) | a.a0);
}

// Ek1..k32(a)=G_[K32]G{K31]...G[K1](a1,a0) where a=a1|a0
uint64_t Magma::encrypt(uint64_t plainText) {
    V32xV32 a = {(uint32_t)(plainText >> 32), (uint32_t)(plainText & 0xffffffff)};
    for (int i=0;i<31;i++) {
        a = G(K[i], a);
    }
    return G_(K[31], a);;
}

// Dk1..k32(a)=G_[K1]G{K2]...G[K32](a1,a0) where a=a1|a0
uint64_t Magma::decrypt(uint64_t cipherText) {
    V32xV32 a = {(uint32_t)(cipherText >> 32), (uint32_t)(cipherText & 0xffffffff)};
    for (int i=31;i>0;i--) {
        a = G(K[i], a);
    }
    return G_(K[0], a);;
}

void Magma::setKey(array<uint32_t,8> cipherKey) {
    copy(begin(cipherKey), end(cipherKey), begin(key));
    keyShedule();
}

//K(1)1=k255|...|k224,...K(8)=k31|...|k0  K(i+8)=K(i) K(i+16)=K(i),K(i+24)=K(9-i) i=1...8
void Magma::keyShedule() {
    for (int i=0;i<8;i++) {
        K[31-i] = K[i+16] = K[i+8] = K[i] = key[i];
    }
}
