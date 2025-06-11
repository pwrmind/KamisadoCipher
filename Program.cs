using System.Security.Cryptography;

namespace KamisadoCipher
{
    // 1. Интерфейсы для компонентов системы
    public interface IEncryptionAlgorithm
    {
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
    }

    public interface IKeyGenerator
    {
        byte[] GenerateKey(byte[] inputKey, int length);
    }

    public interface IMaskSelector
    {
        int SelectMaskIndex(byte currentColor);
    }

    public interface IMaskUpdater
    {
        byte UpdateMask(byte mask, int index);
    }

    public interface IStateManager
    {
        void ResetState(byte initialColor);
        void UpdateState(byte processedByte);
    }

    // 2. Базовая реализация компонентов
    public class Sha256KeyGenerator : IKeyGenerator
    {
        public byte[] GenerateKey(byte[] inputKey, int length)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(inputKey);
            var result = new byte[length];
            Array.Copy(hash, result, Math.Min(length, hash.Length));
            return result;
        }
    }

    public class BasicMaskSelector : IMaskSelector
    {
        public int SelectMaskIndex(byte currentColor)
        {
            return currentColor & 0x07; // Используем 3 младших бита
        }
    }

    public class AdvancedMaskUpdater : IMaskUpdater
    {
        private readonly byte[] sBox = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5
        };

        public byte UpdateMask(byte mask, int index)
        {
            // Применяем S-box для нелинейности
            byte updated = sBox[mask & 0x07];
            // Циклический сдвиг влево
            updated = (byte)((updated << 1) | (updated >> 7));
            // XOR с индексом
            return (byte)(updated ^ index);
        }
    }

    public class CipherStateManager : IStateManager
    {
        private byte _currentColor;

        public void ResetState(byte initialColor)
        {
            _currentColor = initialColor;
        }

        public void UpdateState(byte processedByte)
        {
            _currentColor = processedByte;
        }

        public byte GetCurrentColor() => _currentColor;
    }

    // 3. Основной класс шифра
    public class KamisadoCipher : IEncryptionAlgorithm, IDisposable
    {
        private readonly IKeyGenerator _keyGenerator;
        private readonly IMaskSelector _maskSelector;
        private readonly IMaskUpdater _maskUpdater;
        private readonly IStateManager _stateManager;
        
        private readonly byte[] _masks;
        private readonly byte[] _iv;

        public KamisadoCipher(
            byte[] key, 
            byte[] iv,
            IKeyGenerator keyGenerator,
            IMaskSelector maskSelector,
            IMaskUpdater maskUpdater,
            IStateManager stateManager)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Invalid key");
            
            if (iv == null || iv.Length == 0)
                throw new ArgumentException("Invalid IV");

            _keyGenerator = keyGenerator;
            _maskSelector = maskSelector;
            _maskUpdater = maskUpdater;
            _stateManager = stateManager;
            _iv = (byte[])iv.Clone();
            
            // Генерация масок на основе ключа
            _masks = _keyGenerator.GenerateKey(key, 8);
            Reset();
        }

        public void Reset()
        {
            _stateManager.ResetState(_iv[0]);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            return ProcessData(plaintext, OperationType.Encrypt);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            return ProcessData(ciphertext, OperationType.Decrypt);
        }

        private byte[] ProcessData(byte[] input, OperationType operation)
        {
            var output = new byte[input.Length];
            Reset();

            for (int i = 0; i < input.Length; i++)
            {
                int maskIndex = _maskSelector.SelectMaskIndex(
                    ((CipherStateManager)_stateManager).GetCurrentColor());
                
                byte mask = _masks[maskIndex];
                output[i] = (byte)(input[i] ^ mask);
                
                _masks[maskIndex] = _maskUpdater.UpdateMask(mask, maskIndex);
                _stateManager.UpdateState(
                    operation == OperationType.Encrypt ? output[i] : input[i]);
            }

            return output;
        }

        public void Dispose()
        {
            Array.Clear(_masks, 0, _masks.Length);
        }

        private enum OperationType { Encrypt, Decrypt }
    }

    // 4. Фабрика для удобного создания шифра
    public static class CipherFactory
    {
        public static KamisadoCipher CreateCipher(byte[] key, byte[] iv)
        {
            return new KamisadoCipher(
                key,
                iv,
                new Sha256KeyGenerator(),
                new BasicMaskSelector(),
                new AdvancedMaskUpdater(),
                new CipherStateManager());
        }
    }

    // 5. Пример использования
    class Program
    {
        static void Main()
        {
            byte[] key = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] iv = { 0x1A };
            string original = "Kamisado Secret!";
            
            using var cipher = CipherFactory.CreateCipher(key, iv);
            
            // Шифрование
            byte[] data = System.Text.Encoding.UTF8.GetBytes(original);
            byte[] encrypted = cipher.Encrypt(data);
            
            // Дешифрование (сбрасываем состояние)
            cipher.Reset();
            byte[] decrypted = cipher.Decrypt(encrypted);
            string result = System.Text.Encoding.UTF8.GetString(decrypted);
            
            Console.WriteLine($"Original: {original}");
            Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Decrypted: {result}");
            Console.WriteLine($"Success: {original == result}");
        }
    }
}