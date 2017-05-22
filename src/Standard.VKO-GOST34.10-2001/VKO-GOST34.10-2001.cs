using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop.Samples.Common;

namespace VKO_GOST3410_2001
{
    class VKO_GOST3410_2001
    {
        // Шаблон для поиска закрытого ключа отправителя
        static readonly List<ObjectAttribute> SenderPrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска закрытого ключа получателя
        static readonly List<ObjectAttribute> RecipientPrivateKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId2),
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска открытого ключа отправителя
        static readonly List<ObjectAttribute> SenderPublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId1),
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для поиска открытого ключа получателя
        static readonly List<ObjectAttribute> RecipientPublicKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_ID, SampleConstants.GostKeyPairId2),
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410)
        };

        // Шаблон для создания ключа обмена
        static readonly List<ObjectAttribute> DerivedKeyAttributes = new List<ObjectAttribute>
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.DerivedKeyLabel),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            new ObjectAttribute(CKA.CKA_SENSITIVE, false)
        };

        static readonly List<ObjectAttribute> SessionKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.WrappedKeyLabel),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            new ObjectAttribute(CKA.CKA_SENSITIVE, false),
        };

        static readonly List<ObjectAttribute> UnwrappedKeyAttributes = new List<ObjectAttribute>()
        {
            new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
            new ObjectAttribute(CKA.CKA_LABEL, SampleConstants.UnwrappedKeyLabel),
            new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
            new ObjectAttribute(CKA.CKA_TOKEN, false),
            new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
            new ObjectAttribute(CKA.CKA_PRIVATE, true),
            new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
            new ObjectAttribute(CKA.CKA_SENSITIVE, false),
        };

        // Шаблон для поиска открытого ключа получателя
        public static void Derive_GostR3410_Key(Session session,
            List<ObjectAttribute> privateKeyAttributes,
            List<ObjectAttribute> publicKeyAttributes,
            byte[] ukm, out ObjectHandle derivedKeyHandle)
        {
            // Получить массив хэндлов закрытых ключей
            Console.WriteLine("Getting private key...");
            List<ObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);
            Errors.Check("No private keys found", privateKeys.Count > 0);

            // Получить массив хэндлов открытых ключей
            Console.WriteLine("Getting public key...");
            List<ObjectHandle> publicKeys = session.FindAllObjects(publicKeyAttributes);
            Errors.Check("No public keys found", publicKeys.Count > 0);

            // Получаем значение открытого ключа
            Console.WriteLine("Getting public key value...");
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<ObjectAttribute> publicKeyValue = session.GetAttributeValue(publicKeys[0], attributes);

            // Определение параметров механизма наследования ключа
            Console.WriteLine("Deriving key...");
            var deriveMechanismParams =
                new CkGostR3410DeriveParams(
                    (uint)Extended_CKD.CKD_CPDIVERSIFY_KDF, publicKeyValue[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeys[0], DerivedKeyAttributes);

            Errors.Check("Invalid derived key handle", derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);

            List<ObjectAttribute> derivedKeyValue = session.GetAttributeValue(derivedKeyHandle, attributes);
            Console.WriteLine(" Derived key value:");
            Helpers.PrintByteArray(derivedKeyValue[0].GetValueAsByteArray());
        }

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
                    bool isGostR3410DeriveSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOSTR3410_DERIVE);
                    bool isGostWrapSupported = mechanisms.Contains((CKM)Extended_CKM.CKM_GOST28147_KEY_WRAP);
                    Errors.Check("CKM_GOSTR3410_DERIVE isn`t supported!", isGostR3410DeriveSupported);
                    Errors.Check("CKM_GOST28147_KEY_WRAP isn`t supported!", isGostWrapSupported);

                    // Открыть RW сессию в первом доступном слоте
                    Console.WriteLine("Opening RW session");
                    using (Session session = slot.OpenSession(false))
                    {
                        // Выполнить аутентификацию Пользователя
                        Console.WriteLine("User authentication");
                        session.Login(CKU.CKU_USER, SampleConstants.NormalUserPin);

                        // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                        // для выработки общего ключа
                        Console.WriteLine("Preparing data for deriving and wrapping...");
                        byte[] ukm = session.GenerateRandom(SampleConstants.UKM_LENGTH);

                        // Генерация значения сессионного ключа
                        byte[] sessionKeyValue = session.GenerateRandom(SampleConstants.GOST_28147_KEY_SIZE);

                        Console.WriteLine(" Session key data is:");
                        Helpers.PrintByteArray(sessionKeyValue);
                        Console.WriteLine("Preparing has been completed successfully");

                        // Выработка общего ключа на стороне отправителя
                        Console.WriteLine("Deriving key on the sender's side...");
                        ObjectHandle senderDerivedKeyHandle = null;
                        Derive_GostR3410_Key(session,
                            SenderPrivateKeyAttributes, RecipientPublicKeyAttributes,
                            ukm, out senderDerivedKeyHandle);
                        Console.WriteLine("Key has been derived successfully");

                        // Маскировать сессионный ключ с помощью общего выработанного ключа
                        // на стороне отправителя
                        Console.WriteLine("Wrapping key...");
                        Console.WriteLine(" Creating the GOST 28147-89 key to wrap...");
                        // Выработка ключа, который будет замаскирован
                        ObjectHandle sessionKeyHandle = null;
                        SessionKeyAttributes.Add(new ObjectAttribute(CKA.CKA_VALUE, sessionKeyValue));
                        sessionKeyHandle = session.CreateObject(SessionKeyAttributes);

                        // Определение параметров механизма маскирования
                        var wrapMechanismParams = new CkKeyDerivationStringData(ukm);
                        var wrapMechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                        // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                        byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                        Console.WriteLine("  Wrapped key data is:");
                        Helpers.PrintByteArray(wrappedKey);
                        Console.WriteLine(" Key has been wrapped successfully");

                        // Выработка общего ключа на стороне получателя
                        Console.WriteLine("Deriving key on the sender's side...");
                        ObjectHandle recipientDerivedKeyHandle = null;
                        Derive_GostR3410_Key(session,
                            RecipientPrivateKeyAttributes, SenderPublicKeyAttributes,
                            ukm, out recipientDerivedKeyHandle);
                        Console.WriteLine("Key has been derived successfully");

                        // Демаскирование сессионного ключа с помощью общего выработанного
                        // ключа на стороне получателя
                        Console.WriteLine("Unwrapping key...");
                        ObjectHandle unwrappedKeyHandle =
                            session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, UnwrappedKeyAttributes);

                        Console.WriteLine(" Unwrapped key data is:");
                        Helpers.PrintByteArray(wrappedKey);
                        Console.WriteLine("Unwrapping has been completed successfully");

                        // Сравнение ключа
                        // Получаем публичный ключ по его Id
                            var attributes = new List<CKA>
                        {
                            CKA.CKA_VALUE
                        };
                        List<ObjectAttribute> unwrappedKeyValueAttribute =
                            session.GetAttributeValue(unwrappedKeyHandle, attributes);

                        bool equal = (Convert.ToBase64String(sessionKeyValue) ==
                                      Convert.ToBase64String(unwrappedKeyValueAttribute[0].GetValueAsByteArray()));
                        Errors.Check("Session and unwrapped keys are not equal!", equal);

                        Console.WriteLine("Session and unwrapped keys are equal");

                        // Удаляем сессионный ключ
                        session.DestroyObject(sessionKeyHandle);

                        // Удаляем наследованные ключи
                        session.DestroyObject(senderDerivedKeyHandle);
                        session.DestroyObject(recipientDerivedKeyHandle);

                        // Удаляем размаскированный ключ
                        session.DestroyObject(unwrappedKeyHandle);

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
