#ifndef MID_RSA_RSAENCRYPTOR_H__
#define MID_RSA_RSAENCRYPTOR_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <string>
#include <iostream>
#include <vector>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>


/**
 * 使用流程说明
 * 1. 安装openssl库
 * 2. 使用下面命令生成使用des加密的rsa密钥文件:
 *    eg: openssl genrsa -des3 -out cipherPrv.key 1024 (cipherPrv.key名字由你指定)
 * 3. 使用下面命令生成rsa公钥文件
 *    eg: openssl rsa -in cipherPrv.key -pubout -out cipherPub.key (cipherPub.key名字由你指定)
 * 4. 初始化一个RsaEncryptor对象，传入公钥文件路径名，密钥文件路径名，密钥文件密码
 *    如果仅使用加密，只传入公钥文件路径名就行
 *    eg: RsaEncryptor rsa("cipherPub.key", "cipherPrv.key", "12345")
 * 5. 初始化rsa
 *    eg: EResultInfo result = rsa.init(); 根据EResultInfo枚举判断是否成功或者失败的原因
 * 6. 调用Encrypt进行加密
 *    密文缓冲区的长度为GetPubRsaSize() + 1
 *    EResultInfo result = sa.Encrypt(明文缓冲区，明文长度， 密文接收缓冲区， 密文缓冲区长度)
 * 7. 调用Decrypt进行解密
 *    明文缓冲区的长度为GetPriRsaSize() + 1
 *    EResultInfo result = rsa.Decrypt(密文缓冲区，密文长度， 明文接收缓冲区， 明文缓冲区长度)
 **/
namespace SOpenssl
{

// 声明两个回调函数
void EcosLockingCallback(int mode, int type, const char *file, int line);
unsigned long EcosThreadIdCallback();
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
    };

    enum EKeyMode
    {
        KeyModeFromStr  = 0,        // 字符串
        KeyModeFromFile = 1,        // 文件
    };
public:
    // 使用加密和解密
    RsaEncryptor(const std::string &publicKeyFile, const std::string &privateKeyFile,
            const std::string &password);

    // 仅使用加密
    RsaEncryptor(const std::string &publicKey, const EKeyMode &mode = KeyModeFromFile);

    // 仅使用解密
    RsaEncryptor(const std::string &privateKeyFile, const std::string &password);

    EResultInfo Decrypt(const std::vector<unsigned char> &inData, const unsigned int inDataLen, 
           std::vector<unsigned char> &outData, unsigned int &outDataLen);
    EResultInfo Encrypt(const std::vector<unsigned char> &inData, const unsigned int inDataLen, 
           std::vector<unsigned char> &outData, unsigned int &outDataLen);

    EResultInfo Decrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen);
    EResultInfo Encrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen);

    size_t GetPubRsaSize() const 
    { 
        if (NULL != m_rsaPublic)
            return RSA_size(m_rsaPublic); 
        return 0;
    }
    size_t GetPriRsaSize() const 
    {
        if (NULL != m_rsaPrivate)
            return RSA_size(m_rsaPrivate); 
        return 0;
    }
    
    // 当发生7和8错误的时候，调用该函数获得错误信息
    std::string GetEncrytOrDecryptInfo() const;

    EResultInfo Init();

    void Destory();
    ~RsaEncryptor();

private:
    EResultInfo GetRsaPublic();
    EResultInfo GetRsaPublic(std::string &PublicKey);
    EResultInfo GetRsaPrivate();

    bool m_isInit;
    bool m_isUseEncrypt;
    bool m_isUseDecrypt;
    std::string m_publicKeyFileName;
    std::string m_privateKeyFileName;
    std::string m_password;
    std::string m_publicKeyStr;
    RSA *m_rsaPublic;
    RSA *m_rsaPrivate;
    unsigned long m_rsaErrorNo;
};
}

#endif
