namespace Encryptide
{
    internal enum HandshakeMessageId : ushort
    {
        AsymmetricKey = 0,  // RSA public key
        SymmetricKey = 1,   // Encrypted AES key
        AppSecret = 2       // Shared secret between server and clients for validation
    }
}
