using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace DeleteGOST3410_2012
{
    class DeleteGOST3410_2012
    {
        static readonly List<ObjectAttribute> KeyPair1Attributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId1),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        static readonly List<ObjectAttribute> KeyPair2Attributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.Gost512KeyPairId2),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOSTR3410_512)
        };

        static readonly List<List<ObjectAttribute>> KeyPairsAttributes = new List<List<ObjectAttribute>>
        {
            KeyPair1Attributes,
            KeyPair2Attributes
        };

        static void Main(string[] args)
        {
            // Инициализировать библиотеку
            try
            {
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

                        // Получить массив хэндлов объектов, соответствующих критериям поиска
                        Console.WriteLine("Getting key pairs...");
                        var foundObjects = new List<ObjectHandle>();
                        foreach (var keyPairAttributes in KeyPairsAttributes)
                        {
                            foundObjects.AddRange(session.FindAllObjects(keyPairAttributes));
                        }

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

                        // Сбросить права доступа
                        session.Logout();
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
