#include "RsaEncryptor.h"
#include <assert.h>
#include <mutex>
#include <thread>
#include <vector>
#include <memory>

using namespace SOpenssl;

std::shared_ptr< std::vector<std::mutex> > gLocks;
auto BIODeleter = [] (BIO *bio) { if (nullptr != bio) BIO_free(bio); };
auto RSADeleter = [] (RSA *rsa) { if (nullptr != rsa) RSA_free(rsa); };

// 向openssl提供当前线程号
unsigned long SOpenssl::ThreadIdCallback()
{
    std::this_thread::get_id();
}

// locking回调函数，由openssl库回调，向openssl提供lock/unlock
void SOpenssl::LockingCallback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        (*gLocks)[type].lock();
    }
    else
    {
        (*gLocks)[type].unlock();
    }
}

// 多线程保护初始化
void SOpenssl::ThreadSafetySetup()
{
    gLocks.reset(new std::vector<std::mutex>(CRYPTO_num_locks()));
    CRYPTO_set_id_callback(ThreadIdCallback);
    CRYPTO_set_locking_callback(LockingCallback);
}

// 多线程保护反初始化
void SOpenssl::ThreadSafetyCleanup()
{
    CRYPTO_set_id_callback(nullptr);
    CRYPTO_set_locking_callback(nullptr);
    gLocks.reset();
}

RsaEncryptor::EResultInfo RsaEncryptor::Init()
{
    EResultInfo result = RetSuccess;
    if (true == m_isInit)
        return result;

    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    ThreadSafetySetup();
    if (RetSuccess == result)
        m_isInit = true;
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::SetPublicKeyFromFile(const std::string &publicKeyFile)
{
    auto result = RetSuccess;
    std::shared_ptr<BIO> bio;
    do 
    {
        if (true == m_isUseEncrypt)
        {
            result = RetAlreadyInit;
            break;
        }

        bio.reset(BIO_new_file(publicKeyFile.c_str(), "r"), BIODeleter);
        if (bio.get() == nullptr)
        {
            result = RetCantOpenPublicFile;
            break;
        }

        m_rsaPublic.reset(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                RSADeleter);
        if (nullptr == m_rsaPublic.get())
        {
            result = RetCantReadPublicKey;
            break;
        }
    } while (false);

    if (result == RetSuccess)
        m_isUseEncrypt = true;
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::SetPublicKeyFromStr(std::string &publicKeyStr)
{
    auto result = RetSuccess;
    std::shared_ptr<BIO> bio;
    do
    {
        if (true == m_isUseEncrypt)
        {
            result = RetAlreadyInit;
            break;
        }
        for (std::string::size_type i = 64; i < publicKeyStr.size(); i+=64)
        {
            if (publicKeyStr[i] != '\n')
                publicKeyStr.insert(i, "\n");
            ++i;
        }
        publicKeyStr.insert(0, "-----BEGIN PUBLIC KEY-----\n");
        publicKeyStr.append("\n-----END PUBLIC KEY-----\n");
        bio.reset(BIO_new_mem_buf((void *)publicKeyStr.data(), publicKeyStr.length() + 1),
                BIODeleter);
        if (bio.get() == nullptr)
        {
            result = RetCantOpenPublicFile;
            break;
        }

        m_rsaPublic.reset(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                RSADeleter);
        if (nullptr == m_rsaPublic.get())
        {
            result = RetCantReadPublicKey;
            break;
        }
    } while (false);

    if (RetSuccess == result)
        m_isUseEncrypt = true;
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::SetPrivateKeyFromFile(const std::string &privateKeyFile, 
        std::string password)
{
    auto result = RetSuccess;
    std::shared_ptr<BIO> bio;
    do
    {
        if (true == m_isUseDecrypt)
        {
            result = RetAlreadyInit;
            break;
        }
        
        // 如果密钥文件使用了密钥
        if (!password.empty())
            OpenSSL_add_all_algorithms(); // 一定要调用EVP_cleanup(), 不然内存泄漏;

        bio.reset(BIO_new_file(privateKeyFile.c_str(), "rb"), BIODeleter);
        if (bio.get() == nullptr)
        {
            result = RetCantOpenPrivateFile;
            break;
        }
        
        if (password.empty())
            m_rsaPrivate.reset(PEM_read_bio_RSAPrivateKey(bio.get(),
                    nullptr, nullptr, nullptr), RSADeleter);
        else
            m_rsaPrivate.reset(PEM_read_bio_RSAPrivateKey(bio.get(),
                    nullptr, nullptr, const_cast<char *>(password.c_str())),
                    RSADeleter);
        if (nullptr == m_rsaPrivate)
        {
            result = RetCantReadPrivateKey;
            break;
        }
    } while (false);

    if (RetSuccess == result)
        m_isUseDecrypt = true;
    return result;
}

void RsaEncryptor::Destory()
{
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
    ThreadSafetyCleanup();
}

RsaEncryptor::~RsaEncryptor()
{
    Destory();
}

RsaEncryptor::EResultInfo RsaEncryptor::Decrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen)
{
    EResultInfo result = RetSuccess;
    do
    {
        if (m_isUseDecrypt != true)
        {
            result = RetNoInit;
            break;
        }
        if (outDataLen < RSA_size(m_rsaPrivate.get()))
        {
            result = RetBuffSizeLess;
            break;
        }
        // 解密
        int ret = RSA_private_decrypt(inDataLen, inData, outData,
                m_rsaPrivate.get(), RSA_PKCS1_PADDING);
        if (ret == -1)
        {
            result = RetDecryptError;
            m_rsaErrorNo = ERR_get_error();
            break;
        }
        outDataLen = ret;
    } while(false);
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::Encrypt(const unsigned char *inData, const unsigned int inDataLen, 
           unsigned char *outData, unsigned int &outDataLen)
{
    EResultInfo result = RetSuccess;
    do
    {
        if (m_isUseEncrypt != true)
        {
            result = RetNoInit;
            break;
        }
        if (inDataLen > RSA_size(m_rsaPublic.get()))
        {
            result = RetBuffSizeMore;
            break;
        }
        // 加密
        int ret = RSA_public_encrypt(inDataLen, inData, outData,
                m_rsaPublic.get(), RSA_PKCS1_PADDING);
        if (ret == -1)
        {
            result = RetEncryptError;
            m_rsaErrorNo = ERR_get_error();
            break;
        }
        outDataLen = ret;
    } while(false);
    return result;
}

std::string RsaEncryptor::GetEncrytOrDecryptInfo() const
{
    // 文档说至少120长度
    char errorInfo[120];
    memset(errorInfo, 0, 120);

    ERR_error_string(m_rsaErrorNo, errorInfo);
    return errorInfo;
}
