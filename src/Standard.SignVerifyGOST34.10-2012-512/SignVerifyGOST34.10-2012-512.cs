using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace SignVerifyGOST3410_2012_512
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд вычисления/проверки ЭП на ключах                  *
    * ГОСТ Р 34.10-2012 для длины ключа 512 бит:                             *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - формирование цифровой подписи сообщения на демонстрационном ключе;  *
    *  - проверка цифровой подписи на демонстрационном ключе;                *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST34.10-2012-512.                                              *
    *************************************************************************/

    class SignVerifyGOST3410_2012_512
    {
        // Шаблон для поиска закрытого ключа для цифровой подписи
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY)
        };

        // Шаблон для поиска открытого ключа для проверки цифровой подписи
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            // Класс - открытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
        };

        static void Main(string[] args)
        {
            try
            {
                // Инициализировать библиотеку
                Console.WriteLine("Library initialization");
                using (var pkcs11 = new Pkcs11(Settings.RutokenEcpDllDefaultPath, AppType.MultiThreaded))
                {
                    // Получить доступный слот
                    Console.WriteLine("Checking tokens available");
                    Slot slot = Helpers.GetUsableSlot(pkcs11);

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410_512Supported = mechanisms.Contains((CKM) Extended_CKM.CKM_GOSTR3410_512);
                    bool isGostR3411_12_512Supported = mechanisms.Contains((CKM) Extended_CKM.CKM_GOSTR3411_12_512);
                    Errors.Check(" CKM_GOSTR3410_512 isn`t supported!", isGostR3410_512Supported);
                    Errors.Check(" CKM_GOSTR3411_12_512 isn`t supported!", isGostR3411_12_512Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить данные для вычисления подписи
                            byte[] sourceData = SampleData.Digest_Gost3411_SourceData;

                            // Получить приватный ключ для генерации подписи
                            Console.WriteLine("Getting private key...");
                            List<ObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                            Errors.Check("No private keys found", privateKeys.Count > 0);

                            // Инициализировать операцию хэширования
                            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                            // Вычислить хэш-код данных
                            Console.WriteLine("Hashing data...");
                            byte[] hash = session.Digest(mechanism, sourceData);

                            // Распечатать буфер, содержащий хэш-код
                            Console.WriteLine(" Hashed buffer is:");
                            Helpers.PrintByteArray(hash);
                            Console.WriteLine("Hashing has been completed successfully");

                            // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012-512
                            var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512);

                            // Подписать данные
                            Console.WriteLine("Signing data...");
                            byte[] signature = session.Sign(signMechanism, privateKeys[0], hash);

                            // Распечатать буфер, содержащий подпись
                            Console.WriteLine(" Signature buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("Data has been signed successfully");

                            // Получить публичный ключ для проверки подписи
                            Console.WriteLine("Getting public key...");
                            List<ObjectHandle> publicKeys = session.FindAllObjects(PublicKeyAttributes);
                            Errors.Check("No public keys found", publicKeys.Count > 0);

                            // Проверка подписи для данных
                            Console.WriteLine("Verifying data...");
                            bool isSignatureValid = false;
                            session.Verify(signMechanism, publicKeys[0], hash, signature, out isSignatureValid);

                            if (isSignatureValid)
                                Console.WriteLine("Verifying has been completed successfully");
                            else
                                throw new InvalidOperationException("Invalid signature");
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
