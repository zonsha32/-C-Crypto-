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
        throw runtime_error("�� ������� ������� ����� ��� ����������.");
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
        throw runtime_error("�� ������� ������� ����� ��� �������������.");
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
        cerr << "����� ������� ������: <������� ����> <������������� ����> <�������������� ����> <����> <IV>" << endl;
        return 1;
    }

    try
    {
        // ����� ����� ������
        string inputFileName = argv[1];
        string encryptedFileName = argv[2];
        string decryptedFileName = argv[3];

        // ���� � ������ ������������� (IV)
        string keyHex = argv[4];
        string ivHex = argv[5];

        if (keyHex.length() != GOST::DEFAULT_KEYLENGTH * 2 || ivHex.length() != GOST::BLOCKSIZE * 2)
        {
            throw runtime_error("�������� ����� ����� ��� IV.");
        }

        byte* key = StringToByte(keyHex);
        byte* iv = StringToByte(ivHex);

        // ���������� �����
        EncryptFile(inputFileName, encryptedFileName, key, iv);
        cout << "���� ����������: " << encryptedFileName << endl;

        // ������������� �����
        DecryptFile(encryptedFileName, decryptedFileName, key, iv);
        cout << "���� �����������: " << decryptedFileName << endl;

        delete[] key;
        delete[] iv;
    }
    catch (const Exception& e)
    {
        cerr << "������ Crypto++: " << e.what() << endl;
        return 1;
    }
    catch (const runtime_error& e)
    {
        cerr << "������: " << e.what() << endl;
        return 1;
    }
}