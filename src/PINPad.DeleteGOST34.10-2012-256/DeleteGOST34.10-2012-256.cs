using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace PINPad.DeleteGOST3410_2012_256
{
    /*************************************************************************
    * Rutoken                                                                *
    * Copyright (c) 2003-2019, CJSC Aktiv-Soft. All rights reserved.         *
    * Подробная информация:  http://www.rutoken.ru                           *
    *------------------------------------------------------------------------*
    * Пример работы с Рутокен при помощи библиотеки PKCS#11 на языке C       *
    *------------------------------------------------------------------------*
    * Использование команды удаления объектов PKCS#11:                       *
    *  - установление соединения с Рутокен в первом доступном слоте;         *
    *  - выполнение аутентификации Пользователя;                             *
    *  - удаление ключей ГОСТ Р 34.10-2012                                   *
    *    с длиной закрытого ключа 256 бит;                                   *
    *  - сброс прав доступа Пользователя на Рутокен и закрытие соединения    *
    *    с Рутокен.                                                          *
    *------------------------------------------------------------------------*
    * Пример удаляет ключи, созданные примером                               *
    * PINPad.CreateGOST34.10-2012-256                                        *
    *************************************************************************/

    class DeleteGOST3410_2012_256
    {
        // Шаблон для поиска ключевой пары ГОСТ Р 34.10-2012(256)
        static readonly List<ObjectAttribute> KeyPairAttributes = new List<ObjectAttribute>()
        {
            // Критерий поиска - идентификатор ключевой пары
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost256KeyPairId1),
            // Критерий поиска - ключи ГОСТ Р 34.10-2012(256)
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410)
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
                            // Получить массив хэндлов объектов, соответствующих критериям поиска
                            Console.WriteLine("Getting key pairs...");
                            var foundObjects = session.FindAllObjects(KeyPairAttributes);

                            // Удалить ключи
                            if (foundObjects.Count > 0)
                            {
                                Console.WriteLine("Destroying objects...");
                                int objectsCounter = 1;
                                foreach (var foundObject in foundObjects)
                                {
                                    Console.WriteLine($"   Object №{objectsCounter}");
                                    session.DestroyObject(foundObject);
                                    objectsCounter++;
                                }

                                Console.WriteLine("Objects have been destroyed successfully");
                            }
                            else
                            {
                                Console.WriteLine("No objects found");
                            }
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
