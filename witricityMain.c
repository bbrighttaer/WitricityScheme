

#include <stdio.h>
#include <stdlib.h>

#define PBC_DEBUG //turn on run-time checks
#include "pbc.h"


typedef struct PrivateKeyDetails
{
    element_t R_u;
    element_t s_u;
    element_t usk_u;
}PrivateKey;

typedef struct PublicKeyDetails
{
    element_t upk_u;
}PublicKey;

typedef struct VerificationDetails
{
    element_t verify_innerMul;
    element_t verify_add;
    element_t verify;
}Verify;

typedef struct KeyExchangeDetails
{
    //received details
    element_t h_u;
    element_t upk_u;
    element_t R_u;
    // a or b randomly selected from the group of the order of the curve cyclic group
    element_t randKey;
    //computed and sent/received details
    element_t T_b;
    element_t R_a;
}KeyExchange;

typedef struct SessionKeys
{
    element_t sU;//sRa or sTb
    element_t k_1;
    element_t k_2;
    element_t k_3;
}Keys;

typedef struct PKGDetails
{
    pairing_t pairing;//stores bilinear pairings
    element_t masterkey_x;
    element_t P;//creates an element
    element_t P_pub;
}PKG;

typedef struct Entitys
{
    element_t r_u;
    element_t h_u;
    element_t hx;
    element_t r_u_plus_hx;
    Verify verify_P;
    PrivateKey privateKey;
    PublicKey publicKey;
    KeyExchange keyExchange;
    Keys sessionKeys;
}Entity;

void initPKG(PKG* pkg, char* systemParams);
void initEntity(Entity* entity, PKG* pkg);
void initVerificationDetails(Entity* entity, PKG* pkg);
void initKeyExchangeDetails(Entity* entity, PKG* pkg);
void computeSessionKeys(Entity* entity, PKG* pkg, element_t* el);
unsigned long convertPointToLong(element_t* el);

int main()
{
    //parameters directory
    const char * filename = "param/a.txt";

    //file reading mode
    const char * mode = "r";


    //file object
    FILE *fp;

    //opens the file and sets the mode to read
    fp = fopen( filename,  mode);

    //reads the parameters
    char buff[400];
    fgets(buff, 400, (FILE*)fp);
    fclose( fp );//closes the file
    char * systemParams = buff;

    //entities
    Entity transmitter;
    Entity receiver;
    PKG pkg;

    //initialization of entities NB: PKG has to be the first
    initPKG(&pkg,systemParams);
    initEntity(&transmitter, &pkg);
    initEntity(&receiver, &pkg);

printf("____________________SETUP_______________________________________________\n\n");
    //setup
    element_random(pkg.masterkey_x);
    element_printf("master key x: %B\n\n",pkg.masterkey_x);


    //P := rnd(G1);
    element_random(pkg.P);
    element_printf("P: %B\n\n", pkg.P);

    //P_pub
    element_pow_zn(pkg.P_pub, pkg.P, pkg.masterkey_x);
    element_printf("P_pub: %B\n\n", pkg.P_pub);

printf("_____________________PARTIAL PRIVATE KEY GEN______________________________________________\n\n");

    //Partial private key gen
        //Transmitter
            //r_t
            element_random(transmitter.r_u);
            element_printf("Transmitter's r_u: %B\n\n", transmitter.r_u);

            //R_t
            element_pow_zn(transmitter.privateKey.R_u, pkg.P, transmitter.r_u);//R_u = r_uP
            element_printf("Transmitter's R_u: %B\n\n", transmitter.privateKey.R_u);

            //h_t
            element_random(transmitter.h_u);
            element_printf("Transmitter's h_u: %B\n\n", transmitter.h_u);

            //s_t
                //hx_t
                element_mul(transmitter.hx, transmitter.h_u, pkg.masterkey_x);
                element_printf("Transmitter's hx_u: %B\n\n", transmitter.hx);

                //r_t_plus_hx
                element_add(transmitter.r_u_plus_hx, transmitter.r_u, transmitter.hx);
                element_printf("Transmitter's (r_u + hx): %B\n\n", transmitter.r_u_plus_hx);


            element_invert(transmitter.privateKey.s_u, transmitter.r_u_plus_hx);
            element_printf("Transmitter's s_u: %B\n\n", transmitter.privateKey.s_u);

            //Transmitter verification
            element_pow_zn(transmitter.verify_P.verify_innerMul, pkg.P_pub, transmitter.h_u);
            element_add(transmitter.verify_P.verify_add, transmitter.verify_P.verify_innerMul, transmitter.privateKey.R_u);
            element_pow_zn(transmitter.verify_P.verify, transmitter.verify_P.verify_add, transmitter.privateKey.s_u);
            element_printf("Verify T: %B\n\n", transmitter.verify_P.verify);

            //Compare
            printf("Is Equal?:%i\n\n",element_cmp(pkg.P,transmitter.verify_P.verify));


printf("___________________________________________________________________\n\n");

    //Partial private key gen
        //Receiver
            //r_r
            element_random(receiver.r_u);
            element_printf("Receiver's r_u: %B\n\n", receiver.r_u);

            //R_r
            element_pow_zn(receiver.privateKey.R_u, pkg.P, receiver.r_u);//R_u = r_uP
            element_printf("Receiver's R_u: %B\n\n", receiver.privateKey.R_u);

            //h_r
            element_random(receiver.h_u);
            element_printf("Receiver's h_u: %B\n\n", receiver.h_u);

            //s_r
                //hx_r
                element_mul(receiver.hx, receiver.h_u, pkg.masterkey_x);
                element_printf("Receiver's hx_u: %B\n\n", receiver.hx);

                //r_r_plus_hx
                element_add(receiver.r_u_plus_hx, receiver.r_u, receiver.hx);
                element_printf("Receiver's (r_u + hx): %B\n\n", receiver.r_u_plus_hx);


            element_invert(receiver.privateKey.s_u, receiver.r_u_plus_hx);
            element_printf("Receiver's s_u: %B\n\n", receiver.privateKey.s_u);

            //Receiver verification
            element_pow_zn(receiver.verify_P.verify_innerMul, pkg.P_pub, receiver.h_u);
            element_add(receiver.verify_P.verify_add, receiver.verify_P.verify_innerMul, receiver.privateKey.R_u);
            element_pow_zn(receiver.verify_P.verify, receiver.verify_P.verify_add, receiver.privateKey.s_u);
            element_printf("Verify T: %B\n\n", receiver.verify_P.verify);

            //Compare
            printf("Is Equal?:%i\n\n",element_cmp(pkg.P,receiver.verify_P.verify));


printf("_____________________KEY GEN_____________________________________\n\n");

        //Transmitter
            //Private key
            element_random(transmitter.privateKey.usk_u);
            element_printf("Transmitter's private key: %B\n\n", transmitter.privateKey.usk_u);

            //public key
            element_pow_zn(transmitter.publicKey.upk_u, pkg.P, transmitter.privateKey.usk_u);
            element_printf("Transmitter's public key: %B\n\n", transmitter.publicKey.upk_u);



        //Receiver
            //private key
            element_random(receiver.privateKey.usk_u);
            element_printf("Receiver's private key: %B\n\n", receiver.privateKey.usk_u);
            //public key
            element_pow_zn(receiver.publicKey.upk_u, pkg.P, receiver.privateKey.usk_u);
            element_printf("Receiver's public key: %B\n\n", receiver.publicKey.upk_u);

printf("_____________________KEY EXCHANGE_____________________________________\n");

        //R sends details to T
        element_set(transmitter.keyExchange.h_u, receiver.h_u);
        element_set(transmitter.keyExchange.upk_u, receiver.publicKey.upk_u);
        element_set(transmitter.keyExchange.R_u, receiver.privateKey.R_u);

        //Initial Transmitter operations
        element_random(transmitter.keyExchange.randKey);
        element_printf("\nTransmitter's ephemeral random key b: %B\n",transmitter.keyExchange.randKey);
        element_t inner_pow_t;
        element_init(inner_pow_t, pkg.pairing->G1);
        element_pow_zn(inner_pow_t, pkg.P_pub, transmitter.keyExchange.h_u);
        element_t inner_addition_t;
        element_init(inner_addition_t, pkg.pairing->G1);
        element_add(inner_addition_t, transmitter.keyExchange.R_u, inner_pow_t);
        element_pow_zn(transmitter.keyExchange.T_b, inner_addition_t, transmitter.keyExchange.randKey);
        element_clear(inner_pow_t);
        element_clear(inner_addition_t);
        element_printf("\nT_b: %B\n", transmitter.keyExchange.T_b);

        //T sends details to R
        element_set(receiver.keyExchange.h_u, transmitter.h_u);
        element_set(receiver.keyExchange.upk_u, transmitter.publicKey.upk_u);
        element_set(receiver.keyExchange.R_u, transmitter.privateKey.R_u);
        element_set(receiver.keyExchange.T_b, transmitter.keyExchange.T_b);//computed Tb of transmitter

        //Initial Receiver operations
        element_random(receiver.keyExchange.randKey);
        element_printf("\nReceiver's ephemeral random key b: %B\n",receiver.keyExchange.randKey);
        element_t inner_pow_r;
        element_init(inner_pow_r, pkg.pairing->G1);
        element_pow_zn(inner_pow_r, pkg.P_pub, receiver.keyExchange.h_u);
        element_t inner_addition_r;
        element_init(inner_addition_r, pkg.pairing->G1);
        element_add(inner_addition_r, receiver.keyExchange.R_u, inner_pow_r);
        element_pow_zn(receiver.keyExchange.R_a, inner_addition_r, receiver.keyExchange.randKey);
        element_clear(inner_pow_r);
        element_clear(inner_addition_r);
        element_printf("\nR_a: %B\n", receiver.keyExchange.R_a);

        //Receiver sends R_a to Transmitter
        element_set(transmitter.keyExchange.R_a, receiver.keyExchange.R_a);

printf("_____________________KEY COMPUTATION_____________________________________\n");

        computeSessionKeys(&transmitter, &pkg, &transmitter.keyExchange.R_a);
        element_printf("\nOutput debug T's k1:%B\n", transmitter.sessionKeys.k_1);
        element_printf("\nOutput debug T's k2:%B\n", transmitter.sessionKeys.k_2);
        element_printf("\nOutput debug T's k3:%B\n", transmitter.sessionKeys.k_3);

        computeSessionKeys(&receiver, &pkg, &receiver.keyExchange.T_b);
        element_printf("\nOutput debug R's k1:%B\n", receiver.sessionKeys.k_1);
        element_printf("\nOutput debug R's k2:%B\n", receiver.sessionKeys.k_2);
        element_printf("\nOutput debug R's k3:%B\n", receiver.sessionKeys.k_3);


    return 0;
}

void initPKG(PKG* pkg, char* systemParams)
{
    pairing_init_set_str(pkg->pairing, systemParams);//initialize a pairing
    element_init(pkg->masterkey_x, pkg->pairing->Zr);
    element_init(pkg->P, pkg->pairing->G1);
    element_init(pkg->P_pub, pkg->pairing->G1);
}

void initEntity(Entity* entity, PKG* pkg)
{
    element_init(entity->r_u, pkg->pairing->Zr);
    element_init(entity->privateKey.R_u, pkg->pairing->G1);
    element_init(entity->h_u, pkg->pairing->Zr);
    element_init(entity->hx, pkg->pairing->Zr);
    element_init(entity->r_u_plus_hx, pkg->pairing->Zr);
    element_init(entity->privateKey.s_u, pkg->pairing->Zr);
    element_init(entity->privateKey.usk_u, pkg->pairing->Zr);
    element_init(entity->publicKey.upk_u, pkg->pairing->G1);
    element_init(entity->sessionKeys.sU, pkg->pairing->G1);
    element_init(entity->sessionKeys.k_1, pkg->pairing->G1);
    element_init(entity->sessionKeys.k_2, pkg->pairing->G1);
    element_init(entity->sessionKeys.k_3, pkg->pairing->G1);

    //initialize entity's verification members
    initVerificationDetails(entity, pkg);

    //initialize entity's key exchange members
    initKeyExchangeDetails(entity, pkg);
}

void initVerificationDetails(Entity* entity, PKG* pkg)
{
    element_init(entity->verify_P.verify_innerMul, pkg->pairing->G1);
    element_init(entity->verify_P.verify_add, pkg->pairing->G1);
    element_init(entity->verify_P.verify, pkg->pairing->G1);
}

void initKeyExchangeDetails(Entity* entity, PKG* pkg)
{
    element_init(entity->keyExchange.h_u, pkg->pairing->Zr);
    element_init(entity->keyExchange.upk_u, pkg->pairing->G1);
    element_init(entity->keyExchange.R_u, pkg->pairing->G1);
    element_init(entity->keyExchange.randKey, pkg->pairing->Zr);
    element_init(entity->keyExchange.T_b, pkg->pairing->G1);
    element_init(entity->keyExchange.R_a, pkg->pairing->G1);
}

void computeSessionKeys(Entity* entity,PKG* pkg, element_t* el)
{
    //s_tRa or s_tTb
    element_pow_zn(entity->sessionKeys.sU, *el, entity->privateKey.s_u);
    //K1
    element_pow_zn(entity->sessionKeys.k_1, pkg->P, entity->keyExchange.randKey);
    element_add(entity->sessionKeys.k_1, entity->sessionKeys.sU, entity->sessionKeys.k_1);
    //K2
    element_pow_zn(entity->sessionKeys.k_2, entity->sessionKeys.sU, entity->keyExchange.randKey);
    //K3
    element_t add1;
    element_init(add1, pkg->pairing->G1);
    element_pow_zn(add1, entity->keyExchange.upk_u, entity->keyExchange.randKey);
    element_t add2;
    element_init(add2, pkg->pairing->G1);
    element_pow_zn(add2, entity->sessionKeys.sU, entity->privateKey.usk_u);
    element_add(entity->sessionKeys.k_3, add1, add2);
}

unsigned long convertPointToLong(element_t* el)
{
    mpz_t s_mpz;
    mpz_init(s_mpz);
    element_to_mpz(s_mpz, *el);
    element_printf("\nsdadss:%Z",s_mpz);
    return mpz_get_ui(s_mpz);
}
