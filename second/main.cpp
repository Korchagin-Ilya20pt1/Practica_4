#include <string>
#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>

#include "cryptopp/aes.h"
#include "cryptopp/des.h"
#include "cryptopp/rc2.h"
#include "cryptopp/rc5.h"
#include "cryptopp/rc6.h"
#include "cryptopp/gost.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/twofish.h"
#include "cryptopp/serpent.h"
#include "cryptopp/camellia.h"

#include "cryptopp/modes.h"
#include "cryptopp/cbcmac.h"
#include <locale>

using namespace std;
typedef unsigned char byte;

void encrypt_AES ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::AES ::DEFAULT_KEYLENGTH], iv[CryptoPP::AES ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::AES ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::AES ::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::AES ::Encryption aesEncryption(key, CryptoPP::AES ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_AES ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::AES ::DEFAULT_KEYLENGTH], iv[CryptoPP::AES ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::AES ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::AES ::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::AES ::Decryption aesDecryption(key, CryptoPP::AES ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_DES()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::DES::DEFAULT_KEYLENGTH], iv[CryptoPP::DES::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::DES::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::DES::Encryption aesEncryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_DES()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::DES::DEFAULT_KEYLENGTH], iv[CryptoPP::DES::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::DES::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::DES::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::DES::Decryption aesDecryption(key, CryptoPP::DES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_RC2()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC2::DEFAULT_KEYLENGTH], iv[CryptoPP::RC2::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC2::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC2::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::RC2::Encryption aesEncryption(key, CryptoPP::RC2::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_RC2()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC2::DEFAULT_KEYLENGTH], iv[CryptoPP::RC2::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC2::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC2::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::RC2::Decryption aesDecryption(key, CryptoPP::RC2::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_RC5()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC5::DEFAULT_KEYLENGTH], iv[CryptoPP::RC5::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC5::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC5::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::RC5::Encryption aesEncryption(key, CryptoPP::RC5::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_RC5()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC5::DEFAULT_KEYLENGTH], iv[CryptoPP::RC5::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC5::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC5::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::RC5::Decryption aesDecryption(key, CryptoPP::RC5::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_RC6()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC6::DEFAULT_KEYLENGTH], iv[CryptoPP::RC6::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC6::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC6::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::RC6::Encryption aesEncryption(key, CryptoPP::RC6::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_RC6()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::RC6::DEFAULT_KEYLENGTH], iv[CryptoPP::RC6::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::RC6::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::RC6::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста";
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::RC6::Decryption aesDecryption(key, CryptoPP::RC6::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Введите имя файла для чтения" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_GOST()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::GOST::DEFAULT_KEYLENGTH], iv[CryptoPP::GOST::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::GOST::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::GOST::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::GOST::Encryption aesEncryption(key, CryptoPP::GOST::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_GOST()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::GOST::DEFAULT_KEYLENGTH], iv[CryptoPP::GOST::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::GOST::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::GOST::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::GOST::Decryption aesDecryption(key, CryptoPP::GOST::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_Blowfish ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Blowfish ::DEFAULT_KEYLENGTH], iv[CryptoPP::Blowfish ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Blowfish ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Blowfish ::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::Blowfish ::Encryption aesEncryption(key, CryptoPP::Blowfish ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_Blowfish ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Blowfish ::DEFAULT_KEYLENGTH], iv[CryptoPP::Blowfish ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Blowfish ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Blowfish ::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::Blowfish ::Decryption aesDecryption(key, CryptoPP::Blowfish ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_Twofish ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Twofish ::DEFAULT_KEYLENGTH], iv[CryptoPP::Twofish ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Twofish ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Twofish ::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::Twofish ::Encryption aesEncryption(key, CryptoPP::Twofish ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_Twofish ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Twofish ::DEFAULT_KEYLENGTH], iv[CryptoPP::Twofish ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Twofish ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Twofish ::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::Twofish ::Decryption aesDecryption(key, CryptoPP::Twofish ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_Serpent ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Serpent ::DEFAULT_KEYLENGTH], iv[CryptoPP::Serpent ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Serpent ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Serpent ::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::Serpent ::Encryption aesEncryption(key, CryptoPP::Serpent ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_Serpent ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Serpent ::DEFAULT_KEYLENGTH], iv[CryptoPP::Serpent ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Serpent ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Serpent ::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::Serpent ::Decryption aesDecryption(key, CryptoPP::Serpent ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}
void encrypt_Camellia ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{0};
	string input_file;

	cout << "Введите имя файла для чтения" << endl;
	cin >> input_file;
	ifile.open(input_file);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Camellia ::DEFAULT_KEYLENGTH], iv[CryptoPP::Camellia ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Camellia ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Camellia ::BLOCKSIZE);

	string ciphertext;
	cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext << endl;
	CryptoPP::Camellia ::Encryption aesEncryption(key, CryptoPP::Camellia ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
	stfEncryptor.MessageEnd();
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << endl;
	for (int i = 0; i < ciphertext.size(); i++)
		cout << std::hex << (0xFF & static_cast<byte>(ciphertext[i]));

	cout << endl << "Введите имя новго файла для записи зашифрованного текста" << endl;
	string file_output;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);
	for (int i = 0; i < ciphertext.size(); i++) {
		ofile << ciphertext[i];
	}
}
void decrypt_Camellia ()
{
	setlocale(LC_ALL, "Russia");
	ifstream ifile;
	string plaintext{};
	string file_input;
	cout << "Введите имя файла для чтения" << endl;
	cin >> file_input;
	ifile.open(file_input);
	char ch;
	while (ifile.get(ch))
		plaintext.push_back(ch);

	byte key[CryptoPP::Camellia ::DEFAULT_KEYLENGTH], iv[CryptoPP::Camellia ::BLOCKSIZE];
	memset(key, 0x00, CryptoPP::Camellia ::DEFAULT_KEYLENGTH);
	memset(iv, 0x00, CryptoPP::Camellia ::BLOCKSIZE);

	string file_output;
	cout << "Введите имя новго файла для записи зашифрованного текста" << endl;
	cin >> file_output;
	ofstream ofile;
	ofile.open(file_output);

	string decryptedtext;
	CryptoPP::Camellia ::Decryption aesDecryption(key, CryptoPP::Camellia ::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.size());
	stfDecryptor.MessageEnd();
	cout << "Расшифрованный текст:" << endl;
	cout << decryptedtext << endl;
	ofile << decryptedtext;
}

int main()
{
	setlocale(LC_ALL, "Russia");
	int mode;
	int choice;
	int reload = 1;

	do {
		cout << "Выберете режим \n1 AES \n2 DES \n3 RC2 \n4 RC5 \n5 RC6 \n6 GOST \n7 Blowfish \n8 Twofish \n9 Serpent \n10 Camellia" << endl;
		cin >> mode;
		if (mode <= 10 || mode >= 1) {
			
			cout << "Ведите 1, чтобы зашифровать, 2 дешифровать" << endl;
			cin >> choice;
			
			switch(mode) {
			case 1: {
				if (choice == 1) encrypt_AES();
				else if (choice == 2) decrypt_AES();
				break;
			}
			case 2: {
				if (choice == 1) encrypt_DES();
				else if (choice == 2) decrypt_DES();
				break;
			}
			case 3: {
				if (choice == 1) encrypt_RC2();
				else if (choice == 2) decrypt_RC2();
				break;
			}
			case 4: {
				if (choice == 1) encrypt_RC5();
				else if (choice == 2) decrypt_RC5();
				break;
			}
			case 5: {
				if (choice == 1) encrypt_RC6();
				else if (choice == 2) decrypt_RC6();
				break;
			}
			case 6: {
				if (choice == 1) encrypt_GOST();
				else if (choice == 2) decrypt_GOST();
				break;
			}
			case 7: {
				if (choice == 1) encrypt_Blowfish();
				else if (choice == 2) decrypt_Blowfish();
				break;
			}
			case 8: {
				if (choice == 1) encrypt_Twofish();
				else if (choice == 2) decrypt_Twofish();
				break;
			}
			case 9: {
				if (choice == 1) encrypt_Serpent();
				else if (choice == 2) decrypt_Serpent();
				break;
			}
			case 10: {
				if (choice == 1) encrypt_Camellia();
				else if (choice == 2) decrypt_Camellia();
				break;
			}
			}
			
			cout << "Введите 1 чтобы повторить выбор, 0 выйти" << endl;
			cin >> reload;
		}
	} while(reload == 1);


	return 0;
}