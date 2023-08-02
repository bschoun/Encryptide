using Riptide;
using Riptide.Transports;
using Riptide.Utils;
using System.Security.Cryptography;
using System.Text;

namespace Encryptide
{
    public class Client : Riptide.Client
    {
        /// <summary>
        /// RSA (asymmetric) key. 
        /// Public RSA key will be sent to server when attempting to connect.
        /// </summary>
        private RSA rsa;

        /// <summary>
        /// AES (symmetric) key. 
        /// This will be received from the server (encrypted using our RSA pub key) when the connection is accepted.
        /// </summary>
        private Aes aes;

        /// <summary>
        /// A string that needs to match between client and server to validate the connection.
        /// </summary>
        public string AppSecret { private get; set; } = null;

        /// <summary>
        /// Whether to encrypt data by default.
        /// </summary>
        private bool encryptByDefault = false;

        #region Initialization

        /// <summary>
        /// A client that can send/recieve encrypted data.
        /// </summary>
        /// <param name="logName">Log name</param>
        /// <param name="secret">Shared secret between client and server.</param>
        /// <param name="encryptByDefault">Whether to automatically encrypt data.</param>
        public Client(string logName = "CLIENT", string secret = null, bool encryptByDefault = false) : base(logName)
        {
            // Create own public/private RSA keys
            rsa = RSA.Create();

            if (secret != null)
            {
                // Set the secret identifier shared between server/client
                AppSecret = secret;
            }
            this.encryptByDefault = encryptByDefault;
        }
        #endregion

        #region SendAndReceive

        /// <summary>
        /// Sends a message to the server.
        /// </summary>
        /// <param name="message">Message to send.</param>
        /// <param name="shouldRelease">Whether message should be released.</param>
        /// <param name="encryption">Whether to encrypt message.</param>
        public void Send(Message message, bool shouldRelease = true, Encryption encryption = Encryption.Default)
        {
            message = this.PrepareMessageToSend(message, encryption);
            base.Send(message, shouldRelease);
        }

        /// <summary>
        /// Processes message (decrypts) before running the base method.
        /// </summary>
        /// <param name="message"></param>
        protected override void OnMessageReceived(Message message)
        {
            // Process the message (decrypt if encrypted)
            message = ProcessReceivedMessage(message);
            base.OnMessageReceived(message);
        }
        #endregion

        #region ConnectionHandshake

        /// <summary>
        /// Client attempts to connect to server at hostAddress
        /// </summary>
        /// <param name="ipString"></param>
        public void Connect(string hostAddress)
        {
            if (AppSecret == null)
            {
                RiptideLogger.Log(LogType.Warning, LogName, $"AppSecret was not set. Please set AppSecret in order to connect to a host.");
                return;
            }
            // Create a message to include that has the public RSA key
            Message rsaMessage = Message.Create();
            RSAParameters parameters = rsa.ExportParameters(false);
            rsaMessage.AddBytes(parameters.Modulus, false); // Add modulus, 128 bytes
            rsaMessage.AddBytes(parameters.Exponent, false); // Add exponent, 3 bytes

            // Call the base class's connect function, 
            base.Connect(hostAddress, message: rsaMessage);
        }

        /// <summary>
        /// Overrides Client's Handle function to allow custom handshake.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="header"></param>
        /// <param name="connection"></param>
        protected override void Handle(Message message, MessageHeader header, Connection connection)
        {
            // Before connection, unencrypted (except for sending encrypted AES key)
            if (header == MessageHeader.Reliable && !connection.IsConnected)
            {
                // Process the message (decrypt if encrypted)
                message = ProcessReceivedMessage(message);

                ushort messageId = message.GetUShort();
                switch (messageId)
                {
                    // Server sent public RSA key
                    case (ushort)HandshakeMessageId.AsymmetricKey:
                        RiptideLogger.Log(LogType.Info, LogName, $"Received public RSA key from server {connection}.");
                        SendAppSecret(message);
                        break;
                    // Server sent encrypted AES key
                    case (ushort)HandshakeMessageId.SymmetricKey:
                        RiptideLogger.Log(LogType.Info, LogName, $"Received encrypted AES key from server {connection}.");
                        SetAESEncryption(message.GetBytes(), message.GetBytes());
                        break;
                    default:
                        break;
                }
                message.Release();
                return;
            }

            // Handle like normal after decryption
            base.Handle(message, header, connection);
        }

        /// <summary>
        /// Gets server's public RSA key, then encrypts app secret to send to the server.
        /// </summary>
        /// <param name="message">Message containing server public RSA key.</param>
        public void SendAppSecret(Message message)
        {
            // Create a new RSAParameters object with the information
            RSAParameters serverRsaParameters = new RSAParameters();
            serverRsaParameters.Modulus = message.GetBytes(128);
            serverRsaParameters.Exponent = message.GetBytes(3);
            RSA serverRsa = RSA.Create(serverRsaParameters);

            // Encrypt and send AppSecret
            byte[] decryptedAppSecret = Encoding.UTF8.GetBytes(AppSecret);
            byte[] encryptedAppSecret = serverRsa.Encrypt(decryptedAppSecret);
            Message encryptedMessage = Message.Create(MessageSendMode.Reliable, HandshakeMessageId.AppSecret);
            encryptedMessage.AddBytes(encryptedAppSecret);

            // Send the encrypted secret to the server. The message is already encrypted so don't do it again
            Send(encryptedMessage, encryption: Encryption.None);
        }

        /// <summary>
        /// Decrypts AES key using private RSA key and stores it for future encryption/decryption.
        /// </summary>
        /// <param name="encryptedKey"></param>
        /// <param name="encryptedIV"></param>
        public void SetAESEncryption(byte[] encryptedKey, byte[] encryptedIV)
        {
            aes = Aes.Create();
            aes.Key = rsa.Decrypt(encryptedKey);
            aes.IV = rsa.Decrypt(encryptedIV);
        }

        #endregion

        #region EncryptAndDecrypt

        /// <summary>
        /// Upon receiving a message, remove encrypted byte and possibly decrypt.
        /// </summary>
        /// <param name="message">Message to process.</param>
        /// <returns>A normal message without the encrypt byte.</returns>
        private Message ProcessReceivedMessage(Message message)
        {
            // Get the message id
            ushort messageId = message.GetUShort();
            // Get the encryption type
            byte encryption = message.GetByte();
            // Get the data
            byte[] data = message.GetBytes(message.UnreadLength);

            // Recreate the message (basically resets the readPos/writePos of the message)
            message = Message.Create(message.SendMode, messageId);

            // If the message was encrypted, decrypt it and add the decrypted bytes to the message
            if (encryption == 1)
            {
                message.AddBytes(aes.Decrypt(data), false);
            }
            // If the message isn't encrypted, just add the data as-is
            else
            {
                message.AddBytes(data, false);
            }
            return message;
        }

        /// <summary>
        /// Prepares message to be sent by adding an encryption byte and possibly encrypting the data.
        /// </summary>
        /// <param name="message">Message to be sent.</param>
        /// <param name="encryption">Whether or not to encrypt the data.</param>
        /// <returns>The prepared message.</returns>
        private Message PrepareMessageToSend(Message message, Encryption encryption)
        {
            // Get the id
            ushort messageId = message.GetUShort();

            // Get the entire length of bytes following
            byte[] bytes = message.GetBytes(message.UnreadLength);

            // Recreate the message (basically resets the readPos/writePos of the message)
            message = Message.Create(message.SendMode, messageId);

            // Add a byte that specifies whether the message is encrypted
            if (encryption == Encryption.None || encryption == Encryption.Aes)
            {
                message.AddByte((byte)encryption);
            }
            else if (encryption == Encryption.Default)
            {
                if (encryptByDefault)
                {
                    message.AddByte((byte)1);
                }
                else
                {
                    message.AddByte((byte)0);
                }
            }

            // If we want to encrypt, add the encrypted bytes. If not, add the bytes as-is
            if (encryption == Encryption.Aes || (encryption == Encryption.Default && encryptByDefault))
            {
                message.AddBytes(aes.Encrypt(bytes), false);
            }
            else
            {
                message.AddBytes(bytes, false);
            }
            return message;
        }
        #endregion
    }
}
