using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Samples.Common;

namespace SignVerifyGOST3410_2001
{
    class SignVerifyGOST3410_2001
    {
        // Шаблон для поиска открытого ключа для проверки цифровой подписи
        static readonly List<ObjectAttribute> PublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
        };

        // Шаблон для поиска закрытого ключа для цифровой подписи
        static readonly List<ObjectAttribute> PrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
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

                    // Определение поддерживаемых токеном механизмов
                    Console.WriteLine("Checking mechanisms available");
                    List<CKM> mechanisms = slot.GetMechanismList();
                    Errors.Check("No mechanisms available", mechanisms.Count > 0);
                    bool isGostR3410Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410);
                    bool isGostR3411Supported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3411);
                    Errors.Check("CKM_GOSTR3410 isn`t supported!", isGostR3410Supported);
                    Errors.Check("CKM_GOSTR3411 isn`t supported!", isGostR3411Supported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Получить данные для вычисления подписи
                        byte[] sourceData = SampleData.Digest_Gost3411_SourceData;

                        // Получить приватный ключ для генерации подписи
                        Console.WriteLine("Getting private key...");
                        List<ObjectHandle> privateKeys = session.FindAllObjects(PrivateKeyAttributes);
                        Errors.Check("No private keys found", privateKeys.Count > 0);

                        // Инициализировать операцию хэширования
                        var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

                        // Вычислить хэш-код данных
                        Console.WriteLine("Hashing data...");
                        byte[] hash = session.Digest(mechanism, sourceData);

                        // Распечатать буфер, содержащий хэш-код
                        Console.WriteLine(" Hashed buffer is:");
                        Helpers.PrintByteArray(hash);
                        Console.WriteLine("Hashing has been completed successfully");

                        // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2001
                        var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410);

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
