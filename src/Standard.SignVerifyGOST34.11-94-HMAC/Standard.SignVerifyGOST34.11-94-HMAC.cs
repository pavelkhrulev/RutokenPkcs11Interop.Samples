using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace Standard.SignVerifyGOST3411_94_HMAC
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд выработки HMAC на ключе ГОСТ 28147-89:            *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - создание демонстрационного секретного ключа ГОСТ 28147-89           *
    *    в оперативной памяти;                                               *
    *  - выработка HMAC для сообщения на демонстрационном ключе;             *
    *  - проверка выработки HMAC на демонстрационном ключе;                  *
    *  - удаление созданного ключа, сброс прав доступа Пользователя          *
    *    на Рутокен и закрытие соединения с Рутокен.                         *
    *************************************************************************/

    class SignVerifyGOST3411_94_HMAC
    {
        // Шаблон для создания симметричного ключа ГОСТ 28147-89 в оперативной памяти
        static readonly List<ObjectAttribute> SecretKeyAttributes = new List<ObjectAttribute>
        {
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostSecretKeyLabel),
            // Идентификатор ключа
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostSecretKeyId),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ предназначен для зашифрования
            new ObjectAttribute(CKA.CKA_ENCRYPT, true),
            // Ключ предназначен для расшифрования
            new ObjectAttribute(CKA.CKA_DECRYPT, true),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ недоступен без аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Параметры алгоритма из стандарта
            new ObjectAttribute((uint) Extended_CKA.CKA_GOST28147_PARAMS, SampleConstants.Gost28147Parameters)
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
                    bool isGostR3411_HMACSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411_HMAC);
                    bool isGost28147_89Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOST28147_KEY_GEN);
                    Errors.Check(" CKM_GOSTR3411_HMAC isn`t supported!", isGostR3411_HMACSupported);
                    Errors.Check(" CKM_GOST28147_KEY_GEN isn`t supported!", isGost28147_89Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        ObjectHandle secretkeyHandle = null;

                        try
                        {
                            // Определить механизм генерации ключа
                            Console.WriteLine("Generating GOST 28147-89 secret key...");
                            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_GEN);

                            // Сгенерировать секретный ключ ГОСТ 28147-89
                            secretkeyHandle = session.GenerateKey(mechanism, SecretKeyAttributes);
                            Errors.Check("Invalid key handle", secretkeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                            Console.WriteLine("Generating has been completed successfully");

                            // Инициализация операции HMAC
                            var hmacMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_HMAC);

                            // Выработать HMAC
                            Console.WriteLine("Signing data...");
                            byte[] signature = session.Sign(hmacMechanism, secretkeyHandle, SampleData.Digest_Gost3411_SourceData);

                            // Распечатать буфер, содержащий HMAC
                            Console.WriteLine(" HMAC buffer is:");
                            Helpers.PrintByteArray(signature);
                            Console.WriteLine("HMAC has been computed successfully");

                            // Проверка подписи для данных
                            Console.WriteLine("Verifying HMAC...");
                            bool isSignatureValid;
                            session.Verify(hmacMechanism, secretkeyHandle, SampleData.Digest_Gost3411_SourceData, signature, out isSignatureValid);

                            if (isSignatureValid)
                                Console.WriteLine("Verifying has been completed successfully");
                            else
                                throw new InvalidOperationException("Invalid signature");
                        }
                        finally
                        {
                            // Удаляем секретный ключ
                            if (secretkeyHandle != null)
                            {
                                session.DestroyObject(secretkeyHandle);
                            }

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
