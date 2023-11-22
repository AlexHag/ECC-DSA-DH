using System.Text.Json;

namespace EccDsaDh;

public class Program
{
    public static void Main(string[] args)
    {
        var alice = CryptoService.GenerateKeyPair();
        var bob = CryptoService.GenerateKeyPair();

        var encryptedMessage = CryptoService.EncryptMessage(alice, "Hello, bob!", bob.PublicKey);
        PrintObj(encryptedMessage);
        var valid = CryptoService.DecryptMessage(encryptedMessage, bob.PrivateKey, out string message);

        if (valid)
            Console.WriteLine("Signature is valid...");
        else
            Console.WriteLine("Signature is invalid...");
        Console.WriteLine(message);
    }

    public static void PrintObj(object obj)
        => Console.WriteLine(JsonSerializer.Serialize(obj, new JsonSerializerOptions{ WriteIndented = true }));
}
