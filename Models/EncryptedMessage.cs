namespace EccDsaDh.Models;

public class EncryptedMessage
{
    public required string SenderPublicKey { get; set; }
    public required string RecipientPublicKey { get; set; }
    public required string Cipher { get; set; }
    public required string Signature { get; set; }
}