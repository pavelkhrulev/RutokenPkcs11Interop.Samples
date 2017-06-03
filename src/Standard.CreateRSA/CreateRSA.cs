using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Samples.Common;

namespace CreateRSA
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд создания различных объектов в памяти Рутокен:     *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация ключевой пары RSA;                                        *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Созданные примером объекты используются также и в других примерах      *
    * работы с библиотекой PKCS#11.                                          *
    *************************************************************************/

    class CreateRSA
    {
        // Шаблон для генерации открытого ключа RSA
        // (Ключевая пара для подписи и шифрования)
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>
        {
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.RsaPublicKeyLabel),
            // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Тип ключа - RSA
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ предназначен для зашифрования
            new ObjectAttribute(CKA.CKA_ENCRYPT, true),
            // Ключ доступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Длина модуля ключа
            new ObjectAttribute(CKA.CKA_MODULUS_BITS, SampleConstants.RsaModulusBits)
        };

        // Шаблон для генерации закрытого ключа RSA
        // (Ключевая пара для подписи и шифрования)
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>
        {
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.RsaPrivateKeyLabel),
            // Идентификатор ключевой пары (должен совпадать у открытого и закрытого ключей)
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.RsaKeyPairId),
            // Тип ключа - RSA
            new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
            // Ключ предназначен для расшифрования
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_DECRYPT, true),
            // Ключ доступен только после аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true)
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isRsaSupported = mechanisms.Contains(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);
                    Errors.Check(" CKM_RSA_PKCS_KEY_PAIR_GEN isn`t supported!", isRsaSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Определить механизм генерации ключа
                            Console.WriteLine("Generating RSA key pair...");
                            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

                            // Сгенерировать ключевую пару RSA
                            ObjectHandle publicKeyHandle;
                            ObjectHandle privateKeyHandle;
                            session.GenerateKeyPair(mechanism, PublicKeyAttributes, PrivateKeyAttributes, out publicKeyHandle, out privateKeyHandle);
                            Errors.Check("Invalid public key handle", publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                            Errors.Check("Invalid private key handle", privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

                            Console.WriteLine("Generating has been completed successfully");
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
