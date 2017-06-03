using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Samples.Common;

namespace PINPad.Journal
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2017, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен PINPad при помощи библиотеки PKCS#11 на языке  *
    * C#                                                                     *
    *------------------------------------------------------------------------*
    * Использование команд работы с журналом операций                        *
    *  - установление соединения с Рутокен PINPad в первом доступном слоте;  *
    *  - выполнение аутентификации Пользователя;                             *
    *  - получение журнала операций Рутокен PINPad;                          *
    *  - генерация пары для цифровой подписи журнала на Рутокен PINPad;      *
    *  - цифровая подпись журнала Рутокен PINPad журнальной парой;           *
    *  - проверка цифровой подписи журнала Рутокен PINPad журнальной парой;  *
    *  - сброс прав доступа Пользователя на Рутокен PINPad и закрытие        *
    *    соединения с Рутокен PINPad.                                        *
    *------------------------------------------------------------------------*
    * Для примера необходима хотя бы одна операция формирования ЭЦП,         *
    * например, выполнение примера SignGOST34.10-2001-PINPad.                *
    *************************************************************************/

    class Journal
    {
        // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001 для проверки
        // цифровой подписи журнала
        static readonly List<ObjectAttribute> PublicKeyGenerationAttributes = new List<ObjectAttribute>
        {
            // Объект открытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Тип ключа ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен без аутентификации
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            // Ключ предназначен для проверки цифровой подписи журнала
            new ObjectAttribute((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true)
        };

        // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001 для цифровой
        // подписи журнала
        static readonly List<ObjectAttribute> PrivateKeyGenerationAttributes = new List<ObjectAttribute>
        {
            // Объект закрытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            // Ключ является объектом токена
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            // Ключ доступен только после авторизации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ предназначен для проверки цифровой подписи журнала
            new ObjectAttribute((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true),
            // Операции с ключом не требуют подтверждения на экране Рутокен PINPad
            new ObjectAttribute((uint)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, true)
        };

        // Шаблон для поиска открытого ключа ГОСТ Р 34.10-2001 для проверки
        // цифровой подписи журнала
        static readonly List<ObjectAttribute> PublicKeyFindAttributes = new List<ObjectAttribute>
        {
            // Ключ предназначен для проверки цифровой подписи журнала
            new ObjectAttribute((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true),
            // Объект открытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            // Тип ключа ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2001 для цифровой
        // подписи журнала
        static readonly List<ObjectAttribute> PrivateKeyFindAttributes = new List<ObjectAttribute>
        {
            // Ключ предназначен для проверки цифровой подписи журнала
            new ObjectAttribute((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true),
            // Объект закрытого ключа
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
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

                    // Получить расширенную информацию о подключенном токене
                    Console.WriteLine("Checking token type");
                    TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();
                    // Проверить наличие PINPad в нулевом слоте
                    Errors.Check("Device in slot 0 is not Rutoken PINPad", tokenInfo.TokenType == RutokenType.PINPAD_FAMILY);

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check(" No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410GenSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);
                    bool isGostR3410Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410);
                    bool isGostR3411Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411);
                    Errors.Check(" CKM_GOSTR3410_KEY_PAIR_GEN isn`t supported!", isGostR3410GenSupported);
                    Errors.Check(" CKM_GOSTR3410 isn`t supported!", isGostR3410Supported);
                    Errors.Check(" CKM_GOSTR3411 isn`t supported!", isGostR3411Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        try
                        {
                            // Получить журнал
                            Console.WriteLine("Acquiring journal...");
                            byte[] journal = slot.GetJournal();
                            Errors.Check("Journal is empty!", journal != null);
                            Errors.Check("Journal is empty!", journal.Length > 0);

                            // Распечатать журнал
                            Console.WriteLine(" Journal buffer is:");
                            Helpers.PrintByteArray(journal);
                            Console.WriteLine("Journal has been acquired successfully");

                            // Получить хэндл закрытого ключа журнальной пары
                            Console.WriteLine("Getting journal private key...");
                            List<ObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyFindAttributes);

                            ObjectHandle journalPublicKeyHandle;
                            ObjectHandle journalPrivateKeyHandle;
                            if (privateKeys.Count <= 0)
                            {
                                Console.WriteLine(
                                    "No journal private keys found! Journal key pair will be generated");

                                // Генерировать журнальную ключевую пару
                                var keyGenMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                                session.GenerateKeyPair(keyGenMechanism, PublicKeyGenerationAttributes, PrivateKeyGenerationAttributes,
                                    out journalPublicKeyHandle, out journalPrivateKeyHandle);
                                Errors.Check("Invalid public key handle", journalPublicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                                Errors.Check("Invalid private key handle", journalPrivateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
                            }
                            else
                            {
                                journalPrivateKeyHandle = privateKeys[0];
                            }

                            // Сформировать хэш-код журнала для цифровой подписи
                            Console.WriteLine("Hashing journal...");
                            var digestMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);
                            byte[] journalHash = session.Digest(digestMechanism, journal);

                            // Распечатать буфер, содержащий хэш-код
                            Console.WriteLine(" Hashed buffer is:");
                            Helpers.PrintByteArray(journalHash);
                            Console.WriteLine("Hashing has been completed successfully");

                            // Сформировать цифровую подпись журнала по алгоритму ГОСТ Р 34.10 - 2001
                            Console.WriteLine("Signing journal...");
                            var journalSignMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410);
                            byte[] journalSignature = session.SignInvisible(journalSignMechanism, journalPrivateKeyHandle, journalHash);

                            // Распечатать буфер, содержащий цифровую подпись журнала
                            Console.WriteLine(" Sign buffer is:");
                            Helpers.PrintByteArray(journalSignature);
                            Console.WriteLine("Signing has been completed");

                            // Получать хэндл открытого ключа журнальной пары
                            Console.WriteLine("Getting journal public key...");
                            List<ObjectHandle> publicKeys = session.FindAllObjects(PublicKeyFindAttributes);
                            Errors.Check("No public keys found", publicKeys.Count > 0);
                            journalPublicKeyHandle = publicKeys[0];

                            // Выполнить проверку цифровой подписи по алгоритму ГОСТ Р 34.10-2001
                            Console.WriteLine("Verifying signature...");
                            bool isSignatureValid = false;
                            session.Verify(journalSignMechanism, journalPublicKeyHandle, journalHash, journalSignature, out isSignatureValid);

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
