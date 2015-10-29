#include "RsaEncryptor.h"
#include <assert.h>
#include <pthread.h>

using namespace SOpenssl;

static long *lockCount;
static pthread_mutex_t *lockCs;

// 向openssl提供当前线程号
unsigned long SOpenssl::EcosThreadIdCallback()
{
    pthread_t ret;
    ret = pthread_self();
    return ret;
}

// locking回调函数，由openssl库回调，向openssl提供lock/unlock
void SOpenssl::EcosLockingCallback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
    {
        pthread_mutex_lock(&(lockCs[type]));
        lockCount[type]++;
    }
    else
    {
        pthread_mutex_unlock(&(lockCs[type]));
    }
}

// 多线程保护初始化
void SOpenssl::ThreadSafetySetup()
{
    lockCs = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lockCount = (long *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));

    for (int i = 0; i < CRYPTO_num_locks(); ++i)
    {
        lockCount[i] = 0;
        pthread_mutex_init(&(lockCs[i]), nullptr);
    }

    CRYPTO_set_id_callback(EcosThreadIdCallback);
    CRYPTO_set_locking_callback(EcosLockingCallback);
}

// 多线程保护反初始化
void SOpenssl::ThreadSafetyCleanup()
{
    CRYPTO_set_id_callback(nullptr);
    CRYPTO_set_locking_callback(nullptr);

    for (int i = 0; i < CRYPTO_num_locks(); ++i)
    {
        pthread_mutex_destroy(&(lockCs[i]));
    }
    
    OPENSSL_free(lockCs);
    lockCs = nullptr;
    OPENSSL_free(lockCount);
    lockCount = nullptr;
}

RsaEncryptor::EResultInfo RsaEncryptor::Init()
{
    EResultInfo result = RetSuccess;
    if (true == m_isInit)
        return result;
    do
    {
        // 初始化PublicKey
        if (m_isUseEncrypt == true)
        {
            if (!m_publicKeyStr.empty())
            {
                if ((result = GetRsaPublic(m_publicKeyStr)) != RetSuccess)
                    break;
            }
            else
            {
                if ((result = GetRsaPublic()) != RetSuccess)
                    break;
            }
        }

        if (m_isUseDecrypt == true)
        {
            if ((result = GetRsaPrivate()) != RetSuccess)
                break;
        }
    } while(false);

    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    
    if (RetSuccess == result)
        m_isInit = true;
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::SetPublicKeyFromFile(const std::string &publicKeyFile)
{
    EResultInfo result = RetSuccess;
    std::shared_ptr<FILE> keyfile;
    do 
    {
        if (true == m_isUseEncrypt)
        {
            result = RetAlreadyInit;
            break;
        }

        keyFile.reset(fopen(publicKeyFile.c_str(), "rb"), [](FILE *file){
                if (nullptr != file) fclose(file);});
        if (keyFile.get() == nullptr)
        {
            result = RetCantOpenPublicFile;
            break;
        }

        m_rsaPublic = RSA_new();

        if (PEM_read_RSA_PUBKEY(keyFile.get(), &m_rsaPublic, 0, 0) == nullptr)
        {
            result = RetCantReadPublicKey;
            break;
        }
    } while (false);

    if (result == RetSuccess)
        m_isUseEncrypt = true;
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::GetRsaPublic()
{
    EResultInfo result = RetSuccess;
    FILE *keyFile = nullptr;
    do
    {
        if ((keyFile = fopen(m_publicKeyFileName.c_str(), "rb")) == nullptr)
        {
            result = RetCantOpenPublicFile;
            break;
        }

        m_rsaPublic = RSA_new();
        if (PEM_read_RSA_PUBKEY(keyFile , &m_rsaPublic, 0, 0) == nullptr)
        {
            result = RetCantReadPublicKey;
            break;
        }
    } while(false);

    if (nullptr != keyFile)
    {
       fclose(keyFile); 
    }
    return result;
}

RsaEncryptor::EResultInfo RsaEncryptor::GetRsaPrivate()
{
    EResultInfo result = RetSuccess;
    BIO *bio = nullptr;
    do
    {
        m_rsaPrivate = RSA_new();
        OpenSSL_add_all_algorithms(); // 一定要调用EVP_cleanup(), 不然内存泄漏;
        bio = BIO_new_file(m_privateKeyFileName.c_str(), "rb");
        if (nullptr == bio)
        {
            result = RetCantOpenPrivateFile;
            break;
        }
        
        m_rsaPrivate = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, (void *)m_password.c_str());
        if (nullptr == m_rsaPrivate)
        {
            result = RetCantReadPrivateKey;
            break;
        }
    } while(false);

    if (nullptr != bio)
    {
        BIO_free(bio);
    }
    return result;
}

void RsaEncryptor::Destory()
{
    if (m_rsaPublic != nullptr) RSA_free(m_rsaPublic);
    if (m_rsaPrivate != nullptr) RSA_free(m_rsaPrivate);
    CRYPTO_cleanup_all_ex_data();
    EVP_cleanup();
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
        if (outDataLen < RSA_size(m_rsaPrivate))
        {
            result = RetBuffSizeLess;
            break;
        }
        // 加密
        int ret = RSA_private_decrypt(inDataLen, inData, outData,
                m_rsaPrivate, RSA_PKCS1_PADDING);
        if (ret == -1)
        {
            result = RetDecryptError;
            m_rsaErrorNo = ERR_get_error();
            /*
            std::vector<char> errVect(1024, 0);
            ERR_error_string(ERR_get_error(), errVect.data());
            std::cout << errVect.data() << std::endl;
            */
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
        if (outDataLen < RSA_size(m_rsaPublic))
        {
            result = RetBuffSizeLess;
            break;
        }
        // 加密
        int ret = RSA_public_encrypt(inDataLen, inData, outData,
                m_rsaPublic, RSA_PKCS1_PADDING);
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

RsaEncryptor::EResultInfo RsaEncryptor::GetRsaPublic(std::string &PublicKey)
{
    EResultInfo result = RetSuccess;
    BIO *bio = nullptr;
    for (int i = 64; i < PublicKey.size(); i+=64)
    {
        if (PublicKey[i] != '\n')
        {
            PublicKey.insert(i, "\n");
        }
        ++i;
    }
    PublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
    PublicKey.append("\n-----END PUBLIC KEY-----\n");
    do
    {
        bio = BIO_new_mem_buf((void *)PublicKey.data(), PublicKey.length() + 1);
        m_rsaPublic = PEM_read_bio_RSA_PUBKEY(bio, nullptr, 0, nullptr);
        if (nullptr == m_rsaPublic )
        {
            result = RetCantReadPublicKey;
            break;
        }

    } while(false);

    BIO_free(bio);
    return result;
}
