using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace CreateGOST3410_2001
{
    class CreateGOST3410_2001
    {
        // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
        // (первая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PublicKeyAttributes1 = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPublicKeyLabel1),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters)
        };

        // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
        // (первая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PrivateKeyAttributes1 = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPrivateKeyLabel1),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_DERIVE, true),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411Parameters)
        };

        // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
        // (вторая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PublicKeyAttributes2 = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPublicKeyLabel2),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId2),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, false),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters)
        };

        // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
        // (вторая ключевая пара для подписи и обмена ключами)
        static readonly List<ObjectAttribute> PrivateKeyAttributes2 = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.GostPrivateKeyLabel2),
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId2),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
            new ObjectAttribute(CKA.CKA_TOKEN, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_DERIVE, true),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, SampleConstants.GostR3410Parameters),
            new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, SampleConstants.GostR3411Parameters)
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check("No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);
                    Errors.Check("CKM_GOSTR3410_KEY_PAIR_GEN isn`t supported!", isGostR3410Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Определить механизм генерации ключа
                        Console.WriteLine("Generating GOST R 34.10-2001 exchange key pairs...");
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

                        // Сгенерировать первую ключевую пару ГОСТ Р 34.10-2001
                        ObjectHandle publicKeyHandle1;
                        ObjectHandle privateKeyHandle1;
                        session.GenerateKeyPair(mechanism, PublicKeyAttributes1, PrivateKeyAttributes1, out publicKeyHandle1, out privateKeyHandle1);
                        Errors.Check("Invalid public key 1 handle", publicKeyHandle1.ObjectId != CK.CK_INVALID_HANDLE);
                        Errors.Check("Invalid private key 1 handle", privateKeyHandle1.ObjectId != CK.CK_INVALID_HANDLE);

                        // Сгенерировать вторую ключевую пару ГОСТ Р 34.10-2001
                        ObjectHandle publicKeyHandle2;
                        ObjectHandle privateKeyHandle2;
                        session.GenerateKeyPair(mechanism, PublicKeyAttributes2, PrivateKeyAttributes2, out publicKeyHandle2, out privateKeyHandle2);
                        Errors.Check("Invalid public key 2 handle", publicKeyHandle2.ObjectId != CK.CK_INVALID_HANDLE);
                        Errors.Check("Invalid private key 2 handle", privateKeyHandle2.ObjectId != CK.CK_INVALID_HANDLE);

                        Console.WriteLine("Generating has been completed successfully");

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
