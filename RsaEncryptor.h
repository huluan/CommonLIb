#ifndef MID_RSA_RSAENCRYPTOR_H__
#define MID_RSA_RSAENCRYPTOR_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string>
#include <iostream>
#include <memory>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


namespace SOpenssl
{

// 声明两个回调函数
void LockingCallback(int mode, int type, const char *file, int line);
unsigned long ThreadIdCallback();
// 多线程保护初始化
void ThreadSafetySetup();
// 多线程保护反初始化
void ThreadSafetyCleanup();

class RsaEncryptor
{
public:
    enum EResultInfo
    {
        RetSuccess = 0,                     // 成功
        RetCantOpenPublicFile = 1,          // 打开公钥文件失败
        RetCantOpenPrivateFile = 2,         // 打开私钥文件失败
        RetCantReadPublicKey = 3,           // 读取公钥文件失败
        RetCantReadPrivateKey = 4,          // 读取私钥文件失败
        RetBuffNull = 5,                    // Buff指针是空
        RetBuffSizeLess = 6,                // Buff长度过小
        RetEncryptError = 7,                // 加密错误
        RetDecryptError = 8,                // 解密错误
        RetNoInit = 9,                      // 没有初始化
        RetAlreadyInit = 10,                // 已经初始化
        RetBuffSizeMore = 11,               // 明文的长度过长
    };

public:
    RsaEncryptor() :
        m_isInit(false),
        m_isUseEncrypt(false),
        m_isUseDecrypt(false),
        m_rsaPublic(nullptr),
        m_rsaPrivate(nullptr),
        m_rsaErrorNo(0){}
    RsaEncryptor(const RsaEncryptor &) = delete;
    RsaEncryptor &operator=(const RsaEncryptor &) = delete;

    EResultInfo SetPublicKeyFromFile(const std::string &publicKeyFile);
    EResultInfo SetPublicKeyFromStr(std::string &publicKeyStr);

    EResultInfo SetPrivateKeyFromFile(const std::string &privateKeyFile, std::string password = "");
    EResultInfo SetPrivateKeyFromStr(const std::string &privateKeyFile);

    EResultInfo Decrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen);
    EResultInfo Encrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen);

    size_t GetPubRsaSize() const 
    { 
        if (NULL != m_rsaPublic)
            return RSA_size(m_rsaPublic.get()); 
        return 0;
    }
    size_t GetPriRsaSize() const 
    {
        if (NULL != m_rsaPrivate)
            return RSA_size(m_rsaPrivate.get()); 
        return 0;
    }
    
    // 当发生7和8错误的时候，调用该函数获得错误信息
    std::string GetEncrytOrDecryptInfo() const;

    EResultInfo Init();

    void Destory();
    ~RsaEncryptor();

private:
    bool m_isInit;
    bool m_isUseEncrypt;
    bool m_isUseDecrypt;
    using RSAPtr =  std::shared_ptr<RSA>;
    RSAPtr m_rsaPublic;
    RSAPtr m_rsaPrivate;
    unsigned long m_rsaErrorNo;
};
}

#endif
