using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop.Samples.Common;
using CkGostR3410DeriveParams = RutokenPkcs11Interop.HighLevelAPI.MechanismParams.CkGostR3410DeriveParams;

namespace Standard.VKO_GOST3410_2001
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C#      *
    *------------------------------------------------------------------------*
    * Использование команд выработки ключа обмена                            *
    * и маскирования сессионного ключа:                                      *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - генерация сессионного ключа;                                        *
    *  - генерация UKM;                                                      *
    *  - выработка ключа обмена;                                             *
    *  - маскирование сессионного ключа на выработанном ключе обемена;       *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример использует объекты, созданные в памяти Рутокен примером         *
    * CreateGOST34.10-2001.                                                  *
    *************************************************************************/

    class VKO_GOST3410_2001
    {
        // Шаблон для поиска закрытого ключа отправителя
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>
        {
            // ID пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            // Класс - закрытый ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            // Тип ключа - ГОСТ Р 34.10-2001
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для создания ключа обмена
        static readonly List<ObjectAttribute> DerivedKeyAttributes = new List<ObjectAttribute>
        {
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.DerivedKeyLabel),
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            // Ключ доступен только после аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        // Шаблон сессионного ключа
        static readonly List<ObjectAttribute> SessionKeyAttributes = new List<ObjectAttribute>
        {
            // Метка ключа
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.WrappedKeyLabel),
            // Класс - секретный ключ
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            // Тип ключа - ГОСТ 28147-89
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
            // Ключ является объектом сессии
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            // Ключ может быть изменен после создания
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            // Ключ доступен только после аутентификации на токене
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            // Ключ может быть извлечен в зашифрованном виде
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            // Ключ может быть извлечен в открытом виде
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        /// <summary>
        /// Функция выработки ключа обмена
        /// </summary>
        /// <param name="session">Хэндл сессии</param>
        /// <param name="privateKeyAttributes">Шаблон для поиска закрытого ключа</param>
        /// <param name="ukm">Буфер, содержащий UKM</param>
        /// <param name="derivedKeyHandle">Хэндл выработанного общего ключа</param>
        static void Derive_GostR3410_Key(Session session,
            List<ObjectAttribute> privateKeyAttributes,
            byte[] ukm, out ObjectHandle derivedKeyHandle)
        {
            // Получить массив хэндлов закрытых ключей
            Console.WriteLine("Getting private key...");
            List<ObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);
            Errors.Check("No private keys found", privateKeys.Count > 0);

            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };

            // Определение параметров механизма наследования ключа
            Console.WriteLine("Deriving key...");
            var deriveMechanismParams =
                new CkGostR3410DeriveParams(
                    (uint)Extended_CKD.CKD_CPDIVERSIFY_KDF, SampleData.PublicKeyData_256, ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeys[0], DerivedKeyAttributes);

            Errors.Check("Invalid derived key handle", derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

            try
            {
                // Получить и распечатать значение выработанного ключа
                List<ObjectAttribute> derivedKeyValue = session.GetAttributeValue(derivedKeyHandle, attributes);
                Console.WriteLine(" Derived key value:");
                Helpers.PrintByteArray(derivedKeyValue[0].GetValueAsByteArray());
            }
            catch (Pkcs11Exception)
            {
                // Уничтожаем ключ, если произошла ошибка при чтении значения
                session.DestroyObject(derivedKeyHandle);
                throw;
            }
        }

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
                    bool isGostR3410DeriveSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_DERIVE);
                    bool isGostWrapSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOST28147_KEY_WRAP);
                    Errors.Check(" CKM_GOSTR3410_DERIVE isn`t supported!", isGostR3410DeriveSupported);
                    Errors.Check(" CKM_GOST28147_KEY_WRAP isn`t supported!", isGostWrapSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(SessionType.ReadWrite))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        ObjectHandle sessionKeyHandle = null;
                        ObjectHandle derivedKeyHandle = null;

                        try
                        {
                            // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                            // для выработки общего ключа
                            Console.WriteLine("Preparing data for deriving and wrapping...");
                            byte[] ukm = session.GenerateRandom(SampleConstants.UkmLength);

                            // Генерация значения сессионного ключа
                            byte[] sessionKeyValue = session.GenerateRandom(SampleConstants.Gost28147_KeySize);

                            Console.WriteLine(" Session key data is:");
                            Helpers.PrintByteArray(sessionKeyValue);
                            Console.WriteLine("Preparing has been completed successfully");

                            // Выработка ключа обмена
                            Console.WriteLine("Deriving key...");
                            Derive_GostR3410_Key(session,
                                PrivateKeyAttributes, ukm, out derivedKeyHandle);
                            Console.WriteLine("Key has been derived successfully");

                            // Маскировать сессионный ключ с помощью выработанного ключа обмена
                            Console.WriteLine("Wrapping key...");
                            Console.WriteLine(" Creating the GOST 28147-89 key to wrap...");
                            // Выработка ключа, который будет замаскирован
                            SessionKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, sessionKeyValue));
                            sessionKeyHandle = session.CreateObject(SessionKeyAttributes);

                            // Определение параметров механизма маскирования
                            var wrapMechanismParams = new CkKeyDerivationStringData(ukm);
                            var wrapMechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                            // Маскирование ключа
                            byte[] wrappedKey = session.WrapKey(wrapMechanism, derivedKeyHandle, sessionKeyHandle);

                            Console.WriteLine("  Wrapped key data is:");
                            Helpers.PrintByteArray(wrappedKey);
                            Console.WriteLine(" Key has been wrapped successfully");
                        }
                        finally
                        {
                            Console.WriteLine("Destroying keys");
                            // Удаляем сессионный ключ
                            if (sessionKeyHandle != null)
                            {
                                session.DestroyObject(sessionKeyHandle);
                            }

                            // Удаляем наследованные ключи
                            if (derivedKeyHandle != null)
                            {
                                session.DestroyObject(derivedKeyHandle);
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
