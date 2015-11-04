#include "../../RsaEncryptor.h"
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
std::string publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC7VCLthdNErxB2+iO6PxPhqbXc\
BcOnrv3ZbK2M0SELSfGfG8vT6tZz0Pa18siMxyRuh9OGX8bmpNYWfLRbhAcVd6Fr\
9jxiydO2nKER++0Stm+VrGHmsUbpE2+yK81MNprQCjLjjW67c6uywDmzOfFXhLrs\
neYhnCrbLRiAX/vLNwIDAQAB";

using namespace SOpenssl;
RsaEncryptor gEncryptor;
std::mutex gMutex;

/*
int main()
{ 
    RsaEncryptor encryptor;
    auto result = encryptor.Init();
    std::cout << result << std::endl;
    // result = encryptor.SetPublicKeyFromFile("testPub.key");
    result = encryptor.SetPublicKeyFromStr(publicKey);
    std::cout << result << std::endl;
    result = encryptor.SetPrivateKeyFromFile("test.key", "12345");
    std::cout << result << std::endl;
    std::vector<unsigned char> msg(6, 0);
    memcpy(msg.data(), "12345", 5);
    std::vector<unsigned char> outBuff(encryptor.GetPubRsaSize(), 0);
    unsigned int  outBuffSize = outBuff.size();
    encryptor.Encrypt(msg.data(), msg.size(), outBuff.data(), outBuffSize);
    std::vector<unsigned char> outBuff1(encryptor.GetPriRsaSize(), 0);
    unsigned int outBuff1Size = outBuff1.size();
    encryptor.Decrypt(outBuff.data(), outBuff.size(), outBuff1.data(), outBuff1Size);
    std::cout << outBuff1.data() << std::endl;
    return  0;
}
*/

void ThreadFunc()
{
    for (int i = 0; i < 1000; ++i)
    {
        std::vector<unsigned char> msg(6, 0);
        memcpy(msg.data(), "12345", 5);
        std::vector<unsigned char> outBuff(gEncryptor.GetPubRsaSize(), 0);
        unsigned int outBuffSize = outBuff.size();
        gEncryptor.Encrypt(msg.data(), msg.size(), outBuff.data(), outBuffSize);
        std::vector<unsigned char> outBuff1(gEncryptor.GetPriRsaSize(), 0);
        unsigned int outBuff1Size = outBuff1.size();
        gEncryptor.Decrypt(outBuff.data(), outBuff.size(), outBuff1.data(), outBuff1Size);
        std::lock_guard<std::mutex> lock(gMutex);
        std::cout << outBuff1.data() << std::endl;
    }
}

// mult thread test
int main()
{
    gEncryptor.Init();
    gEncryptor.SetPublicKeyFromStr(publicKey);
    gEncryptor.SetPrivateKeyFromFile("test.key", "12345");
    std::thread t1(ThreadFunc);
    std::thread t2(ThreadFunc);
    t1.join();
    t2.join();
    return 0;
}
