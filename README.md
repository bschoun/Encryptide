# Encryptide - Hybrid Cryptosystem for Riptide Networking
Encryptide is a Unity package that provides a [hybrid cryptosystem](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) layer for [Riptide Networking](https://github.com/RiptideNetworking/Riptide). You can use Encryptide in addition to Riptide to create a multiplayer game that can pass encrypted data back and forth between clients and servers.

**NOTE: This package is currently undergoing alpha testing, and may not work for all use cases at this time.**

## Getting started

### Installation
First, install [Riptide Networking](https://github.com/RiptideNetworking/Riptide) version 2.0.0. Please see [Riptide's installation instructions](https://riptide.tomweiland.net/manual/overview/installation.html).

After Riptide is installed, follow these instructions:

1. In your Unity project, open the Package Manager (*Window* > *Package Manager*).
2. Click the + (plus) button in the top left corner of the window.
3. Select the *Add package from git URL...* option.
4. Enter the following URL: https://github.com/bschoun/Encryptide.git
5. Click 'Add'.

### Usage
Using Encryptide requires very small modifications to a Riptide project. Please review [Riptide's Getting Started](https://riptide.tomweiland.net/manual/overview/getting-started.html) instructions if you're unfamiliar with how to use Riptide.

To use Encryptide, you would need to replace instantiations of ``Riptide.Server`` and ``Riptide.Client`` with ``Encryptide.Server`` and ``Encryptide.Client``, respectively. These classes inherit from their Riptide counterparts, and add encryption/decryption functionality. For example:

```csharp
Encryptide.Server server = new Encryptide.Server();
Encryptide.Client client = new Encryptide.Client();
```
Both of these classes have a member called `AppSecret`, which is used to validate the connection between a client and a server. The same string must be known to both. You would need to set the server's `AppSecret` before calling its `Start` method, and the client's before calling its `Connect()` method.

```csharp
string appSecret = "<APP SECRET - PLEASE REPLACE>";

// Call this sometime before the server's Start() method
server.AppSecret = appSecret;

// Call this sometime before the client's Connect() method
client.AppSecret = appSecret;
```

Alternatively, you can set the server or client's `AppSecret` in their respective constructors by setting the `secret` parameter.

The only other required change is that instead of setting the server's `RelayFilter` variable directly, you need to set it using the server's `SetRelayFilter()` function. For example, instead of setting `RelayFilter` like this:

```csharp
server.RelayFilter = new MessageRelayFilter(typeof(MessageId), MessageId.SpawnPlayer, MessageId.PlayerMovement);
```

you would set it using:

```csharp
server.SetRelayFilter(typeof(MessageId), MessageId.SpawnPlayer, MessageId.PlayerMovement);
```

That's basically it! ``client`` and ``server`` will by default send messages with their data encrypted, and will automatically decrypt incoming messages. However, if you would like to send a message unencrypted, you can call the client or server's ``Send()`` method and set the `encrypted` parameter to `false`:

```csharp
client.Send(message, encrypted: false);
server.Send(message, clientId, encrypted: false);
```

## How it works

### Hybrid RSA/AES handshake

Each client and server generates their own RSA (asymmetric) key at runtime, and the public keys are shared with one another. Each also has a string called AppSecret that needs to match between client and server to validate a connection. The server generates an AES (symmetric) key during runtime, which is encrypted and shared with clients that pass validation. This way the server and clients share a common AES key that is used to encrypt and decrypt data.

The following handshake occurs during each connection attempt by a client:

1. The client sends its public RSA key to the server during the connection attempt.
    ```mermaid
    graph LR;
        Client --> |Client's public RSA key|Server;
    ```

2. The server sends its public RSA key to the client.
    ```mermaid
    graph RL;
        Server --> |Server's public RSA key|Client;
    ```

3. The client encrypts its AppSecret and sends it to the server.

    ```mermaid
    graph LR;
        Client --> |Encrypted AppSecret|Server;
    ```

4. The server decrypts the client's AppSecret and checks if it matches its own. If they don't match, the server rejects the connection. If it matches, the server will encrypt its AES key using the client's public RSA key, and send it to the client.

    ```mermaid
    graph RL;
        Server --> |Encrypted AES key|Client;
    ```

5. The client decrypts the server's AES key. Now the client and server have the same AES key, which they use to encrypt and decrypt data sent to one another.

    ```mermaid
    graph LR;
        Client --> |Encrypted data|Server;
        Server --> |Encrypted data|Client;
    ```
### Message interception
Riptide Messages are intercepted and modified right before sending and immediately after receiving if they have a `Reliable` or `Unreliable` header. The ``Send()`` methods for the client and server pre-process these messages by reconstructing the contents with an added byte to signify whether the contents are encrypted, and (if needed) encrypting all added data. The ``OnMessageReceived()`` methods for the client and server reconstruct the message to remove the added byte and decrypt the message if it is encrypted (unless the server is relaying the message).

A normal `Reliable` or `Unreliable` message is constructed as follows:

| Message Header | Message ID | Data (not encrypted)|
| ----------- | ----------- | ----------- |

After pre-processing in the ``Send()`` method, the message is constructed like this:

| Message Header | Message ID | Encrypted? | Data (possibly encrypted) |
| ----------- | ----------- | ----------- | --------- |

And upon receiving a message and passing it to the ``OnMessageReceived()`` function, the message is decrypted (if needed) and reconstructed into its original form (unless being relayed by the server).

## Known issues

- When a client is acting as a server, it's currently encrypting and decrypting messages sent to itself. Can see if we can somehow disallow that to reduce overhead.
- From a design perspective, there's some method/member hiding going on in `Encryptide.Server` due to some methods not being virtual that I want to be virtual and some members I need to access being private/internal. While not ideal, I chose to do this to avoid making pull requests to Riptide and to avoid maintaining my own fork of Riptide. I can revisit these decisions later when this project is more stable.

This is a fairly new project, so I'm sure there are more issues. Pull requests, issues, and feedback are very much appreciated!



