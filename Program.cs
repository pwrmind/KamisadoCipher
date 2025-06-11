using System;
using System.Security.Cryptography;
using System.Text;

namespace KamisadoCipher
{
    // 1. Интерфейсы
    public interface IEncryptionAlgorithm
    {
        byte[] Encrypt(byte[] data);
        byte[] Decrypt(byte[] data);
        void Reset();
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
        byte GetCurrentColor();
    }

    // 2. Реализации компонентов
    public class Sha256KeyGenerator : IKeyGenerator
    {
        public byte[] GenerateKey(byte[] inputKey, int length)
        {
            using var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(inputKey);
            var result = new byte[length];
            Buffer.BlockCopy(hash, 0, result, 0, Math.Min(length, hash.Length));
            return result;
        }
    }

    public class BasicMaskSelector : IMaskSelector
    {
        public int SelectMaskIndex(byte currentColor) => currentColor & 0x07;
    }

    public class AdvancedMaskUpdater : IMaskUpdater
    {
        private static readonly byte[] SBox = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0
        };

        public byte UpdateMask(byte mask, int index)
        {
            byte updated = SBox[mask & 0x1F];
            return (byte)(((updated << 1) | (updated >> 7)) ^ index);
        }
    }

    public class CipherStateManager : IStateManager
    {
        private byte _currentColor;

        public void ResetState(byte initialColor) => _currentColor = initialColor;
        public void UpdateState(byte processedByte) => _currentColor = processedByte;
        public byte GetCurrentColor() => _currentColor;
    }

    // 3. Основной класс шифра
    public class KamisadoCipher : IEncryptionAlgorithm, IDisposable
    {
        private readonly IKeyGenerator _keyGenerator;
        private readonly IMaskSelector _maskSelector;
        private readonly IMaskUpdater _maskUpdater;
        private readonly IStateManager _stateManager;
        private readonly byte[] _iv;
        
        private readonly byte[] _initialMasks;
        private byte[] _currentMasks;

        public KamisadoCipher(
            byte[] key, 
            byte[] iv,
            IKeyGenerator keyGenerator,
            IMaskSelector maskSelector,
            IMaskUpdater maskUpdater,
            IStateManager stateManager)
        {
            if (key == null || key.Length == 0) throw new ArgumentException("Invalid key");
            if (iv == null || iv.Length == 0) throw new ArgumentException("Invalid IV");

            _keyGenerator = keyGenerator;
            _maskSelector = maskSelector;
            _maskUpdater = maskUpdater;
            _stateManager = stateManager;
            _iv = (byte[])iv.Clone();
            
            _initialMasks = _keyGenerator.GenerateKey(key, 8);
            _currentMasks = (byte[])_initialMasks.Clone();
            Reset();
        }

        public void Reset()
        {
            _stateManager.ResetState(_iv[0]);
            Buffer.BlockCopy(_initialMasks, 0, _currentMasks, 0, _currentMasks.Length);
        }

        public byte[] Encrypt(byte[] plaintext)
        {
            return ProcessData(plaintext, isEncryption: true);
        }

        public byte[] Decrypt(byte[] ciphertext)
        {
            return ProcessData(ciphertext, isEncryption: false);
        }

        private byte[] ProcessData(byte[] input, bool isEncryption)
        {
            var output = new byte[input.Length];
            Reset();

            for (int i = 0; i < input.Length; i++)
            {
                int maskIndex = _maskSelector.SelectMaskIndex(_stateManager.GetCurrentColor());
                byte mask = _currentMasks[maskIndex];
                
                // Применяем операцию XOR
                output[i] = (byte)(input[i] ^ mask);
                
                // Обновляем маску
                _currentMasks[maskIndex] = _maskUpdater.UpdateMask(mask, maskIndex);
                
                // Обновляем состояние на основе:
                // - При шифровании: зашифрованный байт
                // - При дешифровании: полученный шифр-байт (не расшифрованный!)
                _stateManager.UpdateState(isEncryption ? output[i] : input[i]);
            }

            return output;
        }

        public void Dispose()
        {
            Array.Clear(_initialMasks, 0, _initialMasks.Length);
            Array.Clear(_currentMasks, 0, _currentMasks.Length);
        }
    }

    // 4. Фабрика
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

    // 5. Тестирование
    class Program
    {
        static void Main()
        {
            TestEncryptionDecryption();
            TestEmptyData();
            TestResetState();
        }

        static void TestEncryptionDecryption()
        {
            byte[] key = Encoding.UTF8.GetBytes("StrongKamisadoKey");
            byte[] iv = { 0x3F };
            string original = "Kamisado Secret! Привет こんにちは";
            
            using var cipher = CipherFactory.CreateCipher(key, iv);
            
            // Шифрование
            byte[] data = Encoding.UTF8.GetBytes(original);
            byte[] encrypted = cipher.Encrypt(data);
            
            // Дешифрование (со сбросом состояния)
            cipher.Reset();
            byte[] decrypted = cipher.Decrypt(encrypted);
            string result = Encoding.UTF8.GetString(decrypted);
            
            Console.WriteLine("=== Тест шифрования/дешифрования ===");
            Console.WriteLine($"Original:  {original}");
            Console.WriteLine($"Encrypted: {BitConverter.ToString(encrypted)}");
            Console.WriteLine($"Decrypted: {result}");
            Console.WriteLine($"Success:   {original == result}\n");
        }

        static void TestEmptyData()
        {
            byte[] key = { 0x01, 0x02, 0x03 };
            byte[] iv = { 0xFF };
            
            using var cipher = CipherFactory.CreateCipher(key, iv);
            
            byte[] empty = Array.Empty<byte>();
            byte[] encrypted = cipher.Encrypt(empty);
            cipher.Reset();
            byte[] decrypted = cipher.Decrypt(encrypted);
            
            Console.WriteLine("=== Тест пустых данных ===");
            Console.WriteLine($"Empty encrypt: {encrypted.Length} bytes");
            Console.WriteLine($"Empty decrypt: {decrypted.Length} bytes");
            Console.WriteLine($"Success:       {encrypted.Length == 0 && decrypted.Length == 0}\n");
        }

        static void TestResetState()
        {
            byte[] key = Encoding.UTF8.GetBytes("TestKey");
            byte[] iv = { 0x7E };
            string text = "Important message";
            
            using var cipher = CipherFactory.CreateCipher(key, iv);
            
            byte[] data1 = Encoding.UTF8.GetBytes(text);
            byte[] encrypted1 = cipher.Encrypt(data1);
            
            // Повторное шифрование без сброса
            byte[] encrypted2 = cipher.Encrypt(data1);
            
            // Сброс состояния
            cipher.Reset();
            byte[] encrypted3 = cipher.Encrypt(data1);
            
            Console.WriteLine("=== Тест сброса состояния ===");
            Console.WriteLine($"Same input, same state: {BitConverter.ToString(encrypted1) == BitConverter.ToString(encrypted2)}");
            Console.WriteLine($"Same input, reset state: {BitConverter.ToString(encrypted1) == BitConverter.ToString(encrypted3)}");
        }
    }
}