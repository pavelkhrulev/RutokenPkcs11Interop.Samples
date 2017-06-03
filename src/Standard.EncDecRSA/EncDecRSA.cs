using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Samples.Common;

namespace EncDecRSA
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд шифрования/расшифрования на ключе RSA:            *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - шифрование сообщения на демонстрационном ключе RSA;                 *
    *  - расшифрование зашифрованного сообщения на демонстрационном ключе;   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateRSA.                                                             *
    *************************************************************************/

    class EncDecRSA
    {
        // Шаблон для поиска открытого ключа RSA
        static readonly List<ObjectAttribute> RsaPublicKeyAttributes = new List<ObjectAttribute>
        {
            // Идентификатор ключа
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Тип ключа - RSA
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY)
        };

        // Шаблон для поиска закрытого ключа RSA
        static readonly List<ObjectAttribute> RsaPrivateKeyAttributes = new List<ObjectAttribute>
        {
            // Идентификатор ключа
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Тип ключа - RSA
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
        };

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, Settings.OsLockingDefault))
                {
                    // Получить доступный слот
                    Console.WriteLine("Checking tokens available");
                    Slot slot = Helpers.GetUsableSlot(pkcs11);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить данные для шифрования
                            byte[] sourceData = SampleData.Encrypt_RSA_SourceData;

                            // Получить ключ для шифрования
                            Console.WriteLine("Getting public key...");
                            List<ObjectHandle> publicKeys = session.FindAllObjects(RsaPublicKeyAttributes);
                            Errors.Check("No public keys found", publicKeys.Count > 0);

                            // Инициализировать операцию шифрования
                            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS);

                            // Зашифровать данные
                            Console.WriteLine("Encrypting...");
                            byte[] encryptedData = session.Encrypt(mechanism, publicKeys[0], sourceData);

                            // Распечатать буфер, содержащий зашифрованные данные
                            Console.WriteLine(" Encrypting buffer is:");
                            Helpers.PrintByteArray(encryptedData);
                            Console.WriteLine("Encryption has been completed successfully");

                            // Получить ключ для расшифрования
                            Console.WriteLine("Getting private key...");
                            List<ObjectHandle> privateKeys = session.FindAllObjects(RsaPrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Расшифровать данные
                            Console.WriteLine("Decrypting...");
                            byte[] decryptedData = session.Decrypt(mechanism, privateKeys[0], encryptedData);

                            // Распечатать буфер, содержащий расшифрованные данные
                            Console.WriteLine(" Decrypted buffer is:");
                            Helpers.PrintByteArray(decryptedData);
                            Console.WriteLine("Decryption has been completed successfully");

                            // Сравнить исходные данные с расшифрованными
                            bool encryptionState = (Convert.ToBase64String(sourceData) ==
                                                    Convert.ToBase64String(decryptedData));
                            Errors.Check("Source data and decrypted data are not equal", encryptionState);

                            Console.WriteLine("Source data and decrypted data are equal");
                        }
                        finally
                        {
                            // Сбросить права доступа как в случае исключения,
                            // так и в случае успеха.
                            // Сессия закрывается автоматически.
                            session.Logout();
                        }
                    }
                }
            }
            catch (Pkcs11Exception ex)
            {
                Console.WriteLine($"Operation failed [Method: {ex.Method}, RV: {ex.RV}]");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Operation failed [Message: {ex.Message}]");
            }
        }
    }
}
