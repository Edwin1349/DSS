// encfile.cpp : ╧ЁшьхЁ °шЇЁютрэш /фх°шЇЁютрэш  Їрщыр рыуюЁшЄьюь 3DES ё їх°хь SHA, яюфяшёрээ√ь ▌╓╧ 
//

#include "stdafx.h"
#include <stdio.h>

typedef struct
{
	RSA1024KeyExchBLOB kb;
	unsigned __int64 fSize;
} EncFileHeader;

#define BUFFER_SIZE (1<<14)

void main(int argc, char* argv[])
{
	if (argc != 6 || (argv[1][0] != 'e' && argv[1][0] != 'd'))
	{
		puts("Вызов: encfile e|d имя_контейнера файл_ключа исходный_файл конечный_файл\n");
		return;
	}
	HCRYPTPROV hProv;
	if (!::CryptAcquireContext(&hProv, argv[2], MS_DEF_DSS_PROV, PROV_DSS, 0)) //яюыєўрхь ъюэЄхъёЄ
	{
		puts("Не удается получить контекст\n");
		return;
	}
	HANDLE hInFile;
	if ((hInFile = ::CreateFile(argv[4], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) //юЄъЁ√трхь тїюфэющ Їрщы
	{
		HANDLE hOutFile;
		if ((hOutFile = ::CreateFile(argv[5], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE) //юЄъЁ√трхь т√їюфэющ Їрщы
		{
			HANDLE hKeyFile;
			if ((hKeyFile = ::CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) //юЄъЁ√трхь Їрщы ё яєсышўэ√ь ъы■ўюь
			{
				RSAPubKey1024 key;
				DWORD dwLen;
				if (::ReadFile(hKeyFile, &key, sizeof(RSAPubKey1024), &dwLen, NULL)) //ўшЄрхь яєсышўэ√щ ъы■ў
				{
					HCRYPTKEY hPubKey;
					if (::CryptImportKey(hProv, (BYTE*)&key, sizeof(RSAPubKey1024), NULL, 0, &hPubKey)) //ш шьяюЁЄшЁєхь хую
					{
						HCRYPTHASH hHash;
						if (::CryptCreateHash(hProv, CALG_SHA, 0, 0, &hHash)) //ёючфрхь ї¤°
						{
							switch (argv[1][0])
							{
							case 'e':
							{
								HCRYPTKEY hKey;
								if (!::CryptGenKey(hProv, CALG_3DES, CRYPT_EXPORTABLE, &hKey)) //ухэхЁшЁєхь ъы■ў фы  3DES
								{
									puts("Не удается создать ключ 3DES\n");
									break;
								}
								EncFileHeader fh;
								dwLen = sizeof(RSA1024KeyExchBLOB);
								if (::CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, (BYTE*)&fh.kb, &dwLen)) //¤ъёяюЁЄшЁєхь ъы■ў 3DES
								{
									DWORD dwSzLow, dwSzHigh;
									dwSzLow = ::GetFileSize(hInFile, &dwSzHigh); //яюыєўрхь ЁрчьхЁ шёїюфэюую Їрщыр
									unsigned __int64 fSize = (dwSzHigh << 32) + dwSzLow;
									fh.fSize = fSize;
									if (::WriteFile(hOutFile, &fh, sizeof(EncFileHeader), &dwLen, NULL)) //яш°хь ъы■ў ш ЁрчьхЁ шёїюфэюую Їрщыр
									{
										BYTE buf[BUFFER_SIZE + 8]; //8 - чрярё эр padding
										while (fSize)
										{
											if (!::ReadFile(hInFile, buf, BUFFER_SIZE, &dwLen, NULL)) //ўшЄрхь сыюъ фрээ√ї
											{
												puts("Ошибка чтения файла\n");
												break;
											}
											dwSzLow = dwLen;
											if (!::CryptEncrypt(hKey, hHash, fSize <= BUFFER_SIZE, 0, buf, &dwSzLow, sizeof(buf))) //°шЇЁєхь ш їх°шЁєхь хую
											{
												puts("Ошибка шифрования\n");
												break;
											}
											if (!::WriteFile(hOutFile, buf, dwSzLow, &dwSzLow, NULL))
											{
												puts("Ошибка записи\n");
												break;
											}
											fSize -= dwLen;
										}
										if (!fSize) //тёх чр°шЇЁютрыш эюЁьры№эю
										{
											dwLen = sizeof(buf);
											if (::CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, buf, &dwLen)) //яюфяшё√трхь ї¤°
											{
												if (!::WriteFile(hOutFile, buf, dwLen, &dwLen, NULL)) puts("Ошибка записи хеша в файл\n");
												else puts("Шифрование успешно завершено\n");
											}
											else puts("Не удается подписать файл\n");
										}
									}
									else puts("Не удается сохранить ключ 3DES\n");
								}
								else puts("Не удается экспортировать ключ 3DES\n");
								::CryptDestroyKey(hKey);
								break;
							}
							case 'd':
							{
								HCRYPTKEY hPrivKey;
								if (!::CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivKey)) //фюёЄрхь яЁштрЄэ√щ ъы■ў яюы№чютрЄхы 
								{
									puts("Не удается получить приватный ключ из контейнера\n");
									break;
								}
								EncFileHeader fh;
								if (::ReadFile(hInFile, &fh, sizeof(fh), &dwLen, NULL))
								{
									HCRYPTKEY hKey;
									if (::CryptImportKey(hProv, (BYTE*)&fh.kb, sizeof(RSA1024KeyExchBLOB), hPrivKey, 0, &hKey)) //шьяюЁЄшЁєхь ёхёёшюээ√щ ъы■ў
									{
										unsigned __int64 fOrgSize = fh.fSize, fEncSize;
										DWORD dwSzLow, dwSzHigh;
										dwSzLow = GetFileSize(hInFile, &dwSzHigh);
										fEncSize = (dwSzHigh << 32) + dwSzLow - sizeof(EncFileHeader) - 1024 / 8; //ЁрчьхЁ чр°шЇЁютрээ√ї фрээ√ї
										BYTE buf[BUFFER_SIZE];
										while (fEncSize)
										{
											if (!::ReadFile(hInFile, buf, fEncSize >= BUFFER_SIZE ? BUFFER_SIZE : (DWORD)fEncSize, &dwLen, NULL))
											{
												puts("Ошибка чтения\n");
												break;
											}
											dwSzLow = dwLen;
											if (!::CryptDecrypt(hKey, hHash, fEncSize <= BUFFER_SIZE, 0, buf, &dwSzLow)) //Ёрё°шЇЁют√трхь фрээ√х
											{
												puts("Ошибка дешифрования\n");
												break;
											}
											if (!::WriteFile(hOutFile, buf, fOrgSize >= dwSzLow ? dwSzLow : (DWORD)fOrgSize, &dwSzLow, NULL))
											{
												puts("Ошибка записи\n");
												break;
											}
											fEncSize -= dwLen;
											fOrgSize -= dwSzLow;
										}
										if (!fEncSize) //тёх эюЁьры№эю юЄЁрсюЄрыюё№
										{
											if (::ReadFile(hInFile, buf, 1024 / 8, &dwLen, NULL) && dwLen == 1024 / 8) //ўшЄрхь яюфяшё№
											{
												if (!::CryptVerifySignature(hHash, buf, 1024 / 8, hPubKey, NULL, 0)) puts("Ошибка проверки подписи. Возможно файл был поврежден\n");
												else puts("Файл успешно расшифрован\n");
											}
											else puts("Не найдена сигнатура файла\n");
										}
										::CryptDestroyKey(hKey);
									}
									else puts("Не удается импортировать ключ шифрования\n");
								}
								else puts("Ошибка чтения файла\n");
								::CryptDestroyKey(hPrivKey);
							}
							}
							::CryptDestroyHash(hHash);
						}
						else puts("Не удается создать хэш\n");
						::CryptDestroyKey(hPubKey);
					}
					else puts("Не удается импортировать открытый ключ\n");
				}
				else puts("Не удается прочитать файл с публичным ключем\n");
				::CloseHandle(hKeyFile);
			}
			else puts("Не удается открыть файл с публичным ключем\n");
			::CloseHandle(hOutFile);
		}
		else puts("Не удается открыть выходной файл\n");
		::CloseHandle(hInFile);
	}
	else puts("Не удается открыть входной файл\n");
	::CryptReleaseContext(hProv, 0);
}
