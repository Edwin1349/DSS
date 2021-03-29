// encfile.cpp : ������ ����������/������������ ����� ���������� 3DES � ����� SHA, ����������� ��� 
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
		puts("�맮�: encfile e|d ���_���⥩��� 䠩�_���� ��室��_䠩� ������_䠩�\n");
		return;
	}
	HCRYPTPROV hProv;
	if (!::CryptAcquireContext(&hProv, argv[2], MS_DEF_DSS_PROV, PROV_DSS, 0)) //�������� ��������
	{
		puts("�� 㤠���� ������� ���⥪��\n");
		return;
	}
	HANDLE hInFile;
	if ((hInFile = ::CreateFile(argv[4], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) //��������� ������� ����
	{
		HANDLE hOutFile;
		if ((hOutFile = ::CreateFile(argv[5], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL)) != INVALID_HANDLE_VALUE) //��������� �������� ����
		{
			HANDLE hKeyFile;
			if ((hKeyFile = ::CreateFile(argv[3], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL)) != INVALID_HANDLE_VALUE) //��������� ���� � ��������� ������
			{
				RSAPubKey1024 key;
				DWORD dwLen;
				if (::ReadFile(hKeyFile, &key, sizeof(RSAPubKey1024), &dwLen, NULL)) //������ ��������� ����
				{
					HCRYPTKEY hPubKey;
					if (::CryptImportKey(hProv, (BYTE*)&key, sizeof(RSAPubKey1024), NULL, 0, &hPubKey)) //� ����������� ���
					{
						HCRYPTHASH hHash;
						if (::CryptCreateHash(hProv, CALG_SHA, 0, 0, &hHash)) //������� ���
						{
							switch (argv[1][0])
							{
							case 'e':
							{
								HCRYPTKEY hKey;
								if (!::CryptGenKey(hProv, CALG_3DES, CRYPT_EXPORTABLE, &hKey)) //���������� ���� ��� 3DES
								{
									puts("�� 㤠���� ᮧ���� ���� 3DES\n");
									break;
								}
								EncFileHeader fh;
								dwLen = sizeof(RSA1024KeyExchBLOB);
								if (::CryptExportKey(hKey, hPubKey, SIMPLEBLOB, 0, (BYTE*)&fh.kb, &dwLen)) //������������ ���� 3DES
								{
									DWORD dwSzLow, dwSzHigh;
									dwSzLow = ::GetFileSize(hInFile, &dwSzHigh); //�������� ������ ��������� �����
									unsigned __int64 fSize = (dwSzHigh << 32) + dwSzLow;
									fh.fSize = fSize;
									if (::WriteFile(hOutFile, &fh, sizeof(EncFileHeader), &dwLen, NULL)) //����� ���� � ������ ��������� �����
									{
										BYTE buf[BUFFER_SIZE + 8]; //8 - ����� �� padding
										while (fSize)
										{
											if (!::ReadFile(hInFile, buf, BUFFER_SIZE, &dwLen, NULL)) //������ ���� ������
											{
												puts("�訡�� �⥭�� 䠩��\n");
												break;
											}
											dwSzLow = dwLen;
											if (!::CryptEncrypt(hKey, hHash, fSize <= BUFFER_SIZE, 0, buf, &dwSzLow, sizeof(buf))) //������� � �������� ���
											{
												puts("�訡�� ��஢����\n");
												break;
											}
											if (!::WriteFile(hOutFile, buf, dwSzLow, &dwSzLow, NULL))
											{
												puts("�訡�� �����\n");
												break;
											}
											fSize -= dwLen;
										}
										if (!fSize) //��� ����������� ���������
										{
											dwLen = sizeof(buf);
											if (::CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, buf, &dwLen)) //����������� ���
											{
												if (!::WriteFile(hOutFile, buf, dwLen, &dwLen, NULL)) puts("�訡�� ����� �� � 䠩�\n");
												else puts("���஢���� �ᯥ譮 �����襭�\n");
											}
											else puts("�� 㤠���� �������� 䠩�\n");
										}
									}
									else puts("�� 㤠���� ��࠭��� ���� 3DES\n");
								}
								else puts("�� 㤠���� �ᯮ��஢��� ���� 3DES\n");
								::CryptDestroyKey(hKey);
								break;
							}
							case 'd':
							{
								HCRYPTKEY hPrivKey;
								if (!::CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivKey)) //������� ��������� ���� ������������
								{
									puts("�� 㤠���� ������� �ਢ��� ���� �� ���⥩���\n");
									break;
								}
								EncFileHeader fh;
								if (::ReadFile(hInFile, &fh, sizeof(fh), &dwLen, NULL))
								{
									HCRYPTKEY hKey;
									if (::CryptImportKey(hProv, (BYTE*)&fh.kb, sizeof(RSA1024KeyExchBLOB), hPrivKey, 0, &hKey)) //����������� ���������� ����
									{
										unsigned __int64 fOrgSize = fh.fSize, fEncSize;
										DWORD dwSzLow, dwSzHigh;
										dwSzLow = GetFileSize(hInFile, &dwSzHigh);
										fEncSize = (dwSzHigh << 32) + dwSzLow - sizeof(EncFileHeader) - 1024 / 8; //������ ������������� ������
										BYTE buf[BUFFER_SIZE];
										while (fEncSize)
										{
											if (!::ReadFile(hInFile, buf, fEncSize >= BUFFER_SIZE ? BUFFER_SIZE : (DWORD)fEncSize, &dwLen, NULL))
											{
												puts("�訡�� �⥭��\n");
												break;
											}
											dwSzLow = dwLen;
											if (!::CryptDecrypt(hKey, hHash, fEncSize <= BUFFER_SIZE, 0, buf, &dwSzLow)) //�������������� ������
											{
												puts("�訡�� ����஢����\n");
												break;
											}
											if (!::WriteFile(hOutFile, buf, fOrgSize >= dwSzLow ? dwSzLow : (DWORD)fOrgSize, &dwSzLow, NULL))
											{
												puts("�訡�� �����\n");
												break;
											}
											fEncSize -= dwLen;
											fOrgSize -= dwSzLow;
										}
										if (!fEncSize) //��� ��������� ������������
										{
											if (::ReadFile(hInFile, buf, 1024 / 8, &dwLen, NULL) && dwLen == 1024 / 8) //������ �������
											{
												if (!::CryptVerifySignature(hHash, buf, 1024 / 8, hPubKey, NULL, 0)) puts("�訡�� �஢�ન ������. �������� 䠩� �� ���०���\n");
												else puts("���� �ᯥ譮 ����஢��\n");
											}
											else puts("�� ������� ᨣ����� 䠩��\n");
										}
										::CryptDestroyKey(hKey);
									}
									else puts("�� 㤠���� ������஢��� ���� ��஢����\n");
								}
								else puts("�訡�� �⥭�� 䠩��\n");
								::CryptDestroyKey(hPrivKey);
							}
							}
							::CryptDestroyHash(hHash);
						}
						else puts("�� 㤠���� ᮧ���� ���\n");
						::CryptDestroyKey(hPubKey);
					}
					else puts("�� 㤠���� ������஢��� ������ ����\n");
				}
				else puts("�� 㤠���� ������ 䠩� � �㡫��� ���祬\n");
				::CloseHandle(hKeyFile);
			}
			else puts("�� 㤠���� ������ 䠩� � �㡫��� ���祬\n");
			::CloseHandle(hOutFile);
		}
		else puts("�� 㤠���� ������ ��室��� 䠩�\n");
		::CloseHandle(hInFile);
	}
	else puts("�� 㤠���� ������ �室��� 䠩�\n");
	::CryptReleaseContext(hProv, 0);
}
