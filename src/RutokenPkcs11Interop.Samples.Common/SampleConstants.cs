namespace RutokenPkcs11Interop.Samples.Common
{
    public static class SampleConstants
    {
        /// <summary>
        /// PIN of the SO user a.k.a. PUK.
        /// </summary>
        public static string SecurityOfficerPin = @"87654321";

        /// <summary>
        /// PIN of the normal user.
        /// </summary>
        public static string NormalUserPin = @"12345678";

        public static string NewUserPin = @"55555555";

        public static string WrongUserPin = @"00000000";

        public static string LocalPin = @"1234567890";

        public static uint LocalPinId1 = 0x03;

        public static uint LocalPinId2 = 0x1E;

        /* DEMO метка Rutoken ("длинная") */
        public static string TokenLongLabel = @"!!!Sample Rutoken Long-long-long-long-long label!!!";

        /* DEMO метка Rutoken ("обычная") */
        public static string TokenStdLabel = @"!!!Sample Rutoken label!!!";

        /// <summary>
        /// Application name that is used as a label for all objects created by these tests.
        /// </summary>
        public static string ApplicationName = @"RutokenPkcs11Interop";

        /* DEMO-метка открытого ключа RSA */
        public static string RsaPublicKeyLabel = @"Sample RSA Public Key (Aktiv Co.)";

        /* DEMO-метка закрытого ключа RSA */
        public static string RsaPrivateKeyLabel = @"Sample RSA Private Key (Aktiv Co.)";

        /* DEMO ID пары ключей RSA */
        public static string RsaKeyPairId = @"RSA sample keypair ID (Aktiv Co.)";

        /* DEMO-метка симметричного ключа ГОСТ 28147-89 */
        public static string GostSecretKeyLabel = @"Sample GOST 28147 - 89 Secret Key(Aktiv Co.)";

        /* DEMO ID симметричного ключа ГОСТ 28147-89 */
        public static string GostSecretKeyId = @"GOST 28147-89 Secret Key ID (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #1 ГОСТ Р 34.10-2001 */
        public static string GostPublicKeyLabel1 = @"Sample GOST R 34.10-2001 Public Key 1 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #1 ГОСТ Р 34.10-2001 */
        public static string GostPrivateKeyLabel1 = @"Sample GOST R 34.10-2001 Private Key 1 (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #2 ГОСТ Р 34.10-2001 */
        public static string GostPublicKeyLabel2 = @"Sample GOST R 34.10-2001 Public Key 2 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #2 ГОСТ Р 34.10-2001 */
        public static string GostPrivateKeyLabel2 = @"Sample GOST R 34.10-2001 Private Key 2 (Aktiv Co.)";

        /* DEMO ID пары ключей #1 ГОСТ Р 34.10-2001 */
        public static string GostKeyPairId1 = "GOST R 34.10-2001 sample keypair 1 ID (Aktiv Co.)";

        /* DEMO ID пары ключей #2 ГОСТ Р 34.10-2001 */
        public static string GostKeyPairId2 = "GOST R 34.10-2001 sample keypair 2 ID (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PublicKeyLabel1 = @"Sample GOST R 34.10-2012(512) Public Key 1 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PrivateKeyLabel1 = @"Sample GOST R 34.10-2012(512) Private Key 1 (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #2 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PublicKeyLabel2 = @"Sample GOST R 34.10-2012(512) Public Key 2 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #2 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PrivateKeyLabel2 = @"Sample GOST R 34.10-2012(512) Private Key 2 (Aktiv Co.)";

        /* DEMO ID пары ключей #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512KeyPairId1 = @"GOST R 34.10-2012(512) sample keypair 1 ID (Aktiv Co.)";

        /* DEMO ID пары ключей #2 ГОСТ Р 34.10-2012(512) */
        public static string Gost512KeyPairId2 = @"GOST R 34.10-2012(512) sample keypair 2 ID (Aktiv Co.)";

        /* DEMO-метка общего выработанного ключа */
        public static string DerivedKeyLabel = @"Derived GOST 28147-89 key";

        /* DEMO-метка для маскируемого ключа */
        public static string WrappedKeyLabel = @"GOST 28147-89 key to wrap";

        /* DEMO-метка для демаскированного ключа */
        public static string UnwrappedKeyLabel = @"Unwrapped GOST 28147-89 key";

        /* Длина модуля ключа RSA в битах */
        public static uint RsaModulusBits = 512;

        /* Набор параметров КриптоПро A алгоритма ГОСТ 28147-89 */
        public static byte[] Gost28147Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };

        /* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2001 */
        public static byte[] GostR3410Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };

        /* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2012(512) */
        public static byte[] GostR3410_512_Parameters = { 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01 };

        /* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-1994 */
        public static byte[] GostR3411Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };

        /* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-2012(512) */
        public static byte[] GostR3411_512_Parameters = { 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03 };

        /* Размер синхропосылки в байтах */
        public static int UKM_LENGTH = 8;

        /* Размер симметричного ключа ГОСТ 28147-89 в байтах */
        public static int GOST_28147_KEY_SIZE = 32;

        /* Размер открытого ключа ГОСТ Р 34.10-2001 в байтах */
        public static int GOST_3410_KEY_SIZE = 64;

        /* Размер открытого ключа ГОСТ Р 34.10-2012(512) в байтах */
        public static int GOST_3410_12_512_KEY_SIZE = 128;

        /* Максимальное количество попыток ввода PIN-кода для Администратора */
        public static uint MAX_ADMIN_RETRY_COUNT = 10;

        /* Максимальное количество попыток доступа для Пользователя */
        public static uint MAX_USER_RETRY_COUNT = 10;
    }
}
