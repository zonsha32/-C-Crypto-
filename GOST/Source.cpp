#include <iostream>
#include <string>
#include <fstream>
#include "C:\Libraries\cryptopp564\gost.h"
#include "C:\Libraries\cryptopp564\modes.h"
#include "C:\Libraries\cryptopp564\files.h"
#include "C:\Libraries\cryptopp564\cryptlib.h"
#include "C:\Libraries\cryptopp564\hex.h"

using namespace CryptoPP;
using namespace std;

void EncryptFile(const string& inputFileName, const string& encryptedFileName, const byte* key, const byte* iv)
{
    ifstream inputFile(inputFileName, ios::binary);
    ofstream encryptedFile(encryptedFileName, ios::binary);

    if (!inputFile || !encryptedFile)
    {
        throw runtime_error("Не удалось открыть файлы для шифрования.");
    }

    CBC_Mode<GOST>::Encryption encryption;
    encryption.SetKeyWithIV(key, GOST::DEFAULT_KEYLENGTH, iv);

    FileSource(inputFile, true, new StreamTransformationFilter(encryption, new FileSink(encryptedFile)));
}

void DecryptFile(const string& encryptedFileName, const string& decryptedFileName, const byte* key, const byte* iv)
{
    ifstream encryptedFile(encryptedFileName, ios::binary);
    ofstream decryptedFile(decryptedFileName, ios::binary);

    if (!encryptedFile || !decryptedFile)
    {
        throw runtime_error("Не удалось открыть файлы для расшифрования.");
    }

    CBC_Mode<GOST>::Decryption decryption;
    decryption.SetKeyWithIV(key, GOST::DEFAULT_KEYLENGTH, iv);

    FileSource(encryptedFile, true, new StreamTransformationFilter(decryption, new FileSink(decryptedFile)));
}

byte* StringToByte(const string& hex)
{
    byte* bytes = new byte[hex.length() / 2];
    HexDecoder decoder;
    decoder.Put((const byte*)hex.data(), hex.size());
    decoder.MessageEnd();

    word64 size = decoder.MaxRetrievable();
    if (size > (word64)hex.length() / 2)
    {
        throw runtime_error("HexStringToByteArray: Invalid hex string.");
    }

    decoder.Get(bytes, size);
    return bytes;
}

int main(int argc, char* argv[])
{
    setlocale(LC_ALL, "rus");

    if (argc != 6)
    {
        cerr << "Схема входных данных: <входной файл> <зашифрованный файл> <расшифрованный файл> <ключ> <IV>" << endl;
        return 1;
    }

    try
    {
        // Задаём имена файлов
        string inputFileName = argv[1];
        string encryptedFileName = argv[2];
        string decryptedFileName = argv[3];

        // Ключ и вектор инициализации (IV)
        string keyHex = argv[4];
        string ivHex = argv[5];

        if (keyHex.length() != GOST::DEFAULT_KEYLENGTH * 2 || ivHex.length() != GOST::BLOCKSIZE * 2)
        {
            throw runtime_error("Неверная длина ключа или IV.");
        }

        byte* key = StringToByte(keyHex);
        byte* iv = StringToByte(ivHex);

        // Шифрование файла
        EncryptFile(inputFileName, encryptedFileName, key, iv);
        cout << "Файл зашифрован: " << encryptedFileName << endl;

        // Расшифрование файла
        DecryptFile(encryptedFileName, decryptedFileName, key, iv);
        cout << "Файл расшифрован: " << decryptedFileName << endl;

        delete[] key;
        delete[] iv;
    }
    catch (const Exception& e)
    {
        cerr << "Ошибка Crypto++: " << e.what() << endl;
        return 1;
    }
    catch (const runtime_error& e)
    {
        cerr << "Ошибка: " << e.what() << endl;
        return 1;
    }
}