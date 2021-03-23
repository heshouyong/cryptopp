#include <string>
#include <iostream>
#include <ios>

#include "cryptlib.h"
#include "cpu.h"

#include "asn.h"
#include "oids.h"

#include "luc.h"
#include "rsa.h"
#include "xtr.h"
#include "rabin.h"
#include "pubkey.h"
#include "elgamal.h"
#include "xtrcrypt.h"
#include "eccrypto.h"

#include "hex.h"
#include "base64.h"

#include <sha.h>
#include <sm3.h>
#include <files.h>
#include <hex.h>
#include <filters.h>

#include <osrng.h>
#include <integer.h>

#include <pubkey.h>

#include <eccrypto.h>

#include <pubkey.h>

#include <asn.h>
#include <oids.h>

#include <cryptlib.h>

using namespace std;
using namespace CryptoPP;


void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out = cout);

void SavePrivateKey(const PrivateKey& key, const string& file = "ecies.private.key");
void SavePublicKey(const PublicKey& key, const string& file = "ecies.public.key");

void LoadPrivateKey(PrivateKey& key, const string& file = "ecies.private.key");
void LoadPublicKey(PublicKey& key, const string& file = "ecies.public.key");

static const string message("Now is the time for all good men to come to the aide of their country.");

void test()
{
    AutoSeededRandomPool prng;
    ECIES<ECP,SM3>::Decryptor decryptor;
    const char *pri = "ef20269fdb6fba2d3bf552e1873bc3c64f6faed91967d79d3d53f5f05bbcb934h";
    Integer y = Integer(pri);
    decryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::sm2p256v1());
    decryptor.AccessKey().SetPrivateExponent(y);

    ECIES<ECP,SM3>::Encryptor e0(decryptor);
    /*
    Integer x(prng, Integer::One(), decryptor.AccessKey().GetGroupParameters().GetSubgroupOrder()-1);
    decryptor.AccessKey().SetPrivateExponent(x);
    */
    
    //PrintPrivateKey(decryptor.GetKey());
    /*
    //plaintext
    const char *tempkey    = "a1bfd80d296993e5d31421f911d61ea1ee2d4eb0543f35ff3cbbdd902ff5222f";
    const char *ciphertext = "e0e6ae0da82d3cc43e3d8580a799dab6";
    const char *tag    =     "1a03ab793387dc659f93bb11f4d0edcf7714aa2c08aaf1b807d17e9e8dce1a89";
    const char* plaintext =  "ca44ef8df325abb38dac3743dd3243df";

    string pubx = "a1bfd80d296993e5d31421f911d61ea1ee2d4eb0543f35ff3cbbdd902ff5222f";
    string puby = "a6ed150d11b5aa63df08e94e46481864b27288d0ea7bd559c364d719b4e3e55d";

    //decompress pubkey
    string em0,dm0;
    em0 = "04" + string(pubx) + string(puby) + string(ciphertext) + string(tag);
    
    string strkct;
    printf("em0 = %s\n", em0.c_str());
    StringSource ss (em0, true, new HexDecoder(new StringSink(strkct)));
    em0 = strkct;
    printf("em0 = %ld\n"  , em0.length() );
    //StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(dm0)));
    */
    string plaintext = "ca44ef8df325abb38dac3743dd3243df";
    string strplain = plaintext;
    string em0,dm0;
    //StringSource ss1 (string(plaintext), true, new HexDecoder(new StringSink(strplain)));
    printf("message = %s len = %ld\n", message.c_str(), message.length());
    #if 0
    StringSource ss2 (message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
    #else
    dm0 = "042687a41292fce51b27e3355e0555a4a656fa1f122f5fd5853ac01e30fbb361b261ae07edbd51da290653af4b49765d8404f9b0afc5dfa644a79774a4d4286f082526914fa7b16efbdebb8cab1d1b75a4a14f658bcafc6c1f0be19d51b0780c65796068f576baa42e980c664246f50083574fc95b2ffb2f9f8aff1716b0242252d558cefb3664596e21169f017c9f60fa2e2e75318a355120fcc1bf28d3b8e3238eec7e87003f";
    //dm0 = "04a1bfd80d296993e5d31421f911d61ea1ee2d4eb0543f35ff3cbbdd902ff5222fa6ed150d11b5aa63df08e94e46481864b27288d0ea7bd559c364d719b4e3e55d";
    //dm0 += "e0e6ae0da82d3cc43e3d8580a799dab6";
    //dm0 += "1a03ab793387dc659f93bb11f4d0edcf7714aa2c08aaf1b807d17e9e8dce1a89";
    em0 = "";
    StringSource ss22(dm0, true, new HexDecoder(new StringSink(em0)));
    printf("size = %ld\n",em0.size());
    #endif

    printf("em0: len = %ld\n", em0.length());
    for(int i=0;i<em0.length();i++)
    {
        printf("%02x", (uint8_t)em0.data()[i]);
    }
    printf("\n");

    AutoSeededRandomPool prng1;
    dm0 = "";
    StringSource ss3 (em0, true, new PK_DecryptorFilter(prng1, decryptor, new StringSink(dm0) ) );
    printf("em0 = %ld\n", em0.length());
    for(int i=0;i<em0.length();i++)
    {
        printf("%02x", (uint8_t)em0.data()[i]);
    }
    printf("\n");
    printf("dm0 = %s\n", dm0.c_str());
}
void test1()
{
    printf("test1\n");
    //ECDSA<ECP, SHA256>::PublicKey pubKey;
    //pubKey.AccessGroupParameters().Initialize(ASN1::secp256r1());
    ECDSA<ECP, SM3>::PublicKey pubKey;
    pubKey.AccessGroupParameters().Initialize(ASN1::sm2p256v1());
    /*
    std::string compactPoint = "02" // compressed
    "937120662418500f3ad7c892b1db7e7c"
    "2d85ec48c74e99d64dcb7083082bb4f3";
    */
    std::string compactPoint = "03"
    "a1bfd80d296993e5d31421f911d61ea1ee2d4eb0543f35ff3cbbdd902ff5222f";

    string strkct;
    StringSource ss (compactPoint, true, new HexDecoder());
    
    ECP::Point point;

    printf("before DecodePoint\n");
    pubKey.GetGroupParameters().GetCurve().DecodePoint (point, ss,
    ss.MaxRetrievable());

    std::cout << "Result after decompression X: " << std::hex <<
    point.x << std::endl;
    std::cout << "Result after decompression Y: " << std::hex <<
    point.y << std::endl;

}
int main(int argc, char* argv[])
{
    printf("Hello Croptopp\n");
    //test();
    //return 0;
    AutoSeededRandomPool prng(true);
    printf("AutoSeededRandomPool finished\n");
    /////////////////////////////////////////////////
    // Part one - generate keys
    
    ECIES<ECP>::Decryptor d0(prng, /*ASN1::secp256r1()*/ASN1::sm2p256v1());
    PrintPrivateKey(d0.GetKey());
    printf("Decryptor finished\n");
    

    ECIES<ECP>::Encryptor e0(d0);
    PrintPublicKey(e0.GetKey());
    printf("Encryptor finished\n");
    
    
    /////////////////////////////////////////////////
    // Part two - save keys
    //   Get* returns a const reference
    SavePrivateKey(d0.GetPrivateKey());
    SavePublicKey(e0.GetPublicKey());
    
    
    /////////////////////////////////////////////////
    // Part three - load keys
    //   Access* returns a non-const reference
    
    ECIES<ECP,CryptoPP::SM3>::Decryptor d1;
    LoadPrivateKey(d1.AccessPrivateKey());
    d1.GetPrivateKey().ThrowIfInvalid(prng, 3);
    
    ECIES<ECP,CryptoPP::SM3>::Encryptor e1;
    LoadPublicKey(e1.AccessPublicKey());
    e1.GetPublicKey().ThrowIfInvalid(prng, 3);
    
    /////////////////////////////////////////////////
    // Part four - encrypt/decrypt with e0/d1
    
    string em0; // encrypted message
    StringSource ss1 (message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
    string dm0; // decrypted message
    StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d1, new StringSink(dm0) ) );
    printf("message len = %ld\n" , message.length());
    printf("em len = %ld\n" , em0.length() );
    for(int i=0;i<em0.length();i++)
    {
        printf("%02x ", (uint8_t)em0.data()[i]);
    }
    printf("sub = %ld \n" ,  em0.length() - message.length());
    cout << dm0 << endl;
    
    /////////////////////////////////////////////////
    // Part five - encrypt/decrypt with e1/d0
    
    string em1; // encrypted message
    StringSource ss3 (message, true, new PK_EncryptorFilter(prng, e1, new StringSink(em1) ) );
    string dm1; // decrypted message
    StringSource ss4 (em1, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm1) ) );
    
    cout << dm1 << endl;
    
    return 0;
}

void SavePrivateKey(const PrivateKey& key, const string& file)
{
    FileSink sink(file.c_str());
    key.Save(sink);
}

void SavePublicKey(const PublicKey& key, const string& file)
{
    FileSink sink(file.c_str());
    key.Save(sink);
}

void LoadPrivateKey(PrivateKey& key, const string& file)
{
    FileSource source(file.c_str(), true);
    key.Load(source);
}

void LoadPublicKey(PublicKey& key, const string& file)
{
    FileSource source(file.c_str(), true);
    key.Load(source);
}

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
{
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Base precomputation (for public key calculation from private key)
    const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
    // Public Key (just do the exponentiation)
    const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
    
    out << "Private Exponent (multiplicand): " << endl;
    out << "  " << std::hex << key.GetPrivateExponent() << endl;
}

void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out)
{
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Public key
    const ECPPoint& point = key.GetPublicElement();
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
}
