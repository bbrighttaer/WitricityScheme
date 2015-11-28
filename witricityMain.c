

#include <stdio.h>
#include <stdlib.h>

#define PBC_DEBUG //turn on run-time checks
#include "pbc.h"

typedef struct VerificationDetails
{
    element_t verify_innerMul;
    element_t verify_add;
    element_t verify;
}Verify;

typedef struct KeyExchangeDetails
{

}KeyExchange;

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
    element_t R_u;
    element_t h_u;
    element_t hx;
    element_t r_u_plus_hx;
    element_t s_u;
    element_t usk_u;
    element_t upk_u;
    Verify verify_P;
    KeyExchange keyExchange;
}Entity;

void initPKG(PKG* pkg, char* systemParams);
void initEntity(Entity* entity, PKG* pkg);
void initVerificationDetails(Entity* entity, PKG* pkg);

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
            element_pow_zn(transmitter.R_u, pkg.P, transmitter.r_u);//R_u = r_uP
            element_printf("Transmitter's R_u: %B\n\n", transmitter.R_u);

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


            element_invert(transmitter.s_u, transmitter.r_u_plus_hx);
            element_printf("Transmitter's s_u: %B\n\n", transmitter.s_u);

            //Transmitter verification
            element_pow_zn(transmitter.verify_P.verify_innerMul, pkg.P_pub, transmitter.h_u);
            element_add(transmitter.verify_P.verify_add, transmitter.verify_P.verify_innerMul, transmitter.R_u);
            element_pow_zn(transmitter.verify_P.verify, transmitter.verify_P.verify_add, transmitter.s_u);
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
            element_pow_zn(receiver.R_u, pkg.P, receiver.r_u);//R_u = r_uP
            element_printf("Receiver's R_u: %B\n\n", receiver.R_u);

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


            element_invert(receiver.s_u, receiver.r_u_plus_hx);
            element_printf("Receiver's s_u: %B\n\n", receiver.s_u);

            //Receiver verification
            element_pow_zn(receiver.verify_P.verify_innerMul, pkg.P_pub, receiver.h_u);
            element_add(receiver.verify_P.verify_add, receiver.verify_P.verify_innerMul, receiver.R_u);
            element_pow_zn(receiver.verify_P.verify, receiver.verify_P.verify_add, receiver.s_u);
            element_printf("Verify T: %B\n\n", receiver.verify_P.verify);

            //Compare
            printf("Is Equal?:%i\n\n",element_cmp(pkg.P,receiver.verify_P.verify));


printf("_____________________KEY GEN_____________________________________\n\n");

        //Transmitter
            //Private key
            element_random(transmitter.usk_u);
            element_printf("Transmitter's private key: %B\n\n", transmitter.usk_u);

            //public key
            element_pow_zn(transmitter.upk_u, pkg.P, transmitter.usk_u);
            element_printf("Transmitter's public key: %B\n\n", transmitter.upk_u);



        //Receiver
            //private key
            element_random(receiver.usk_u);
            element_printf("Receiver's private key: %B\n\n", receiver.usk_u);
            //public key
            element_pow_zn(receiver.upk_u, pkg.P, receiver.usk_u);
            element_printf("Receiver's public key: %B\n\n", receiver.upk_u);
/*
printf("_____________________KEY EXCHANGE_____________________________________\n\n");
*/

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
    element_init(entity->R_u, pkg->pairing->G1);
    element_init(entity->h_u, pkg->pairing->Zr);
    element_init(entity->hx, pkg->pairing->Zr);
    element_init(entity->r_u_plus_hx, pkg->pairing->Zr);
    element_init(entity->s_u, pkg->pairing->Zr);
    element_init(entity->usk_u, pkg->pairing->Zr);
    element_init(entity->upk_u, pkg->pairing->G1);

    //initialize entity's verification members
    initVerificationDetails(entity, pkg);
}

void initVerificationDetails(Entity* entity, PKG* pkg)
{
    element_init(entity->verify_P.verify_innerMul, pkg->pairing->G1);
    element_init(entity->verify_P.verify_add, pkg->pairing->G1);
    element_init(entity->verify_P.verify, pkg->pairing->G1);
}
