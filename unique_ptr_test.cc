// #include <openssl/rsa.h>
// #include <openssl/pem.h>
#include <memory>
#include <iostream>
// #include "unique_ptr.h"

 //auto deleter = [](int *sum){delete sum;};
// typedef std::unique_ptr<int, decltype([](int *sum){delete sum;}) > IntPtr;
//typedef std::unique_ptr<int> IntPtr;
//using IntPtr = std::unique_ptr<int, decltype(deleter)>;


int main()
{
    /*
    auto deleter = [](RSA *rsa){
        std::cout << "delete" << std::endl;
        RSA_free(rsa);
    };

    // std::unique_ptr<RSA, decltype(deleter)> rsaPtr(nullptr, deleter);
    RSAPtr rsaPtr(nullptr, deleter);
    RSA *testPtr = RSA_new();
    rsaPtr.reset(testPtr);
    std::unique_ptr<int> testInt;
    int *p = new int(10);
    testInt.reset(p, [](int *num){
            delete num;});
    */
    /*
    std::unique_ptr<int> IntPtr;
    int *p = new int(10);
    IntPtr.reset(p, [](int *num){std::cout << "delete" << std::endl;});
    */
    std::shared_ptr<FILE> pFile1;
    std::shared_ptr<FILE> pFile(nullptr, [](FILE *file){ 
            std::cout << "a1" << std::endl;
            if (nullptr != file)
            {
                std::cout << "delete" << std::endl;
                fclose(file);
            }});
    FILE *pTemp = fopen("./README.md", "rb");
    std::cout << pTemp << std::endl;
    if (pTemp == NULL)
        std::cout << "null" << std::endl;
    pFile.reset(pTemp);
    if (pFile.get() == nullptr)
    {
        std::cout << "12311" << std::endl;
    }
    /*
    pFile1.reset(pTemp, [](FILE *file){ if (nullptr != file)
            {
                std::cout << "delete" << std::endl;
                fclose(file);
            }});
            */
    return 0;
}
