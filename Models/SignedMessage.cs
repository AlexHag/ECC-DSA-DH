namespace EccDsaDh.Models;

public class SignedMessage
{
    public required string PublicKey { get; set; }
    public required string Signature { get; set; }
    public required string MessageHash { get; set; }
}
