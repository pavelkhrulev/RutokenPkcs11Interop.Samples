using System;
using System.Collections.Generic;
using System.Text;
using Net.Pkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11Interop.Samples.Common
{
    public static class Helpers
    {
        public static Slot GetUsableSlot(Pkcs11 pkcs11)
        {
            // Получить список слотов c подключенными токенами
            List<Slot> slots = pkcs11.GetSlotList(true);

            // Проверить, что слоты найдены
            if (slots == null)
                throw new NullReferenceException("No available slots");

            // Проверить, что число слотов больше 0
            if (slots.Count <= 0 )
                throw new InvalidOperationException("No available slots");

            // Получить первый доступный слот
            Slot slot = slots[0];

            return slot;
        }

        public static void PrintByteArray(byte[] array)
        {
            var hexString = new StringBuilder();
            var width = 16;
            int byteCounter = 1;
            foreach (var item in array)
            {
                hexString.AppendFormat(" 0x{0:x2}", item);
                if (byteCounter == width)
                {
                    hexString.AppendLine();
                    byteCounter = 0;
                }
                byteCounter++;
            }

            Console.WriteLine(hexString);
        }
    }
}
