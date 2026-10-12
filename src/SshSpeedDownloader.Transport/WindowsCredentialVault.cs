using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport.IdentityProviders;

namespace SshSpeedDownloader.Transport;

public sealed class WindowsCredentialVault : IPrivatePassphraseStore
{
    private const uint GenericCredential = 1;
    private const uint PersistLocalMachine = 2;
    private const int ErrorNotFound = 1168;
    private const int MaximumCredentialBytes = 5120;

    public static string GetTargetName(SshConnectionProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var keyIdentity = profile.PrivateKeyIdentityId;
        if (string.IsNullOrWhiteSpace(keyIdentity))
            keyIdentity = Path.GetFullPath(profile.PrivateKeyPath);
        var identity = string.Join(
            '|',
            profile.Host.Trim().ToLowerInvariant(),
            profile.Port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            profile.Username,
            keyIdentity);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
        return $"MoDiDownloader/SSH/{Convert.ToHexString(hash)}";
    }

    public void SavePassphrase(string targetName, ReadOnlySpan<char> passphrase)
    {
        EnsureWindows();
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        if (passphrase.IsEmpty)
            throw new ArgumentException("Passphrase cannot be empty.", nameof(passphrase));

        var blob = new byte[Encoding.Unicode.GetByteCount(passphrase)];
        _ = Encoding.Unicode.GetBytes(passphrase, blob);
        if (blob.Length > MaximumCredentialBytes)
        {
            CryptographicOperations.ZeroMemory(blob);
            throw new ArgumentOutOfRangeException(nameof(passphrase));
        }

        var blobPointer = Marshal.AllocHGlobal(blob.Length);
        try
        {
            Marshal.Copy(blob, 0, blobPointer, blob.Length);
            var credential = new NativeCredential
            {
                Type = GenericCredential,
                TargetName = targetName,
                UserName = "MoDi Downloader",
                CredentialBlobSize = (uint)blob.Length,
                CredentialBlob = blobPointer,
                Persist = PersistLocalMachine
            };

            if (!CredWriteW(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(blob);
            ZeroAndFree(blobPointer, blob.Length);
        }
    }

    public char[]? TryReadPassphrase(string targetName)
    {
        EnsureWindows();
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        if (!CredReadW(targetName, GenericCredential, 0, out var credentialPointer))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == ErrorNotFound)
                return null;
            throw new Win32Exception(error);
        }

        try
        {
            var credential = Marshal.PtrToStructure<NativeCredential>(credentialPointer);
            if (credential.CredentialBlobSize == 0 || credential.CredentialBlobSize > MaximumCredentialBytes)
                return null;

            var blob = new byte[credential.CredentialBlobSize];
            try
            {
                Marshal.Copy(credential.CredentialBlob, blob, 0, blob.Length);
                return Encoding.Unicode.GetChars(blob);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(blob);
            }
        }
        finally
        {
            CredFree(credentialPointer);
        }
    }

    public void ForgetPassphrase(string targetName)
    {
        EnsureWindows();
        ArgumentException.ThrowIfNullOrWhiteSpace(targetName);
        if (!CredDeleteW(targetName, GenericCredential, 0))
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorNotFound)
                throw new Win32Exception(error);
        }
    }

    private static void EnsureWindows()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows Credential Manager is available only on Windows.");
    }

    private static void ZeroAndFree(IntPtr pointer, int length)
    {
        if (pointer == IntPtr.Zero)
            return;
        for (var index = 0; index < length; index++)
            Marshal.WriteByte(pointer, index, 0);
        Marshal.FreeHGlobal(pointer);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NativeCredential
    {
        public uint Flags;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? Comment;
        public long LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string? TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UserName;
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredWriteW(ref NativeCredential credential, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredReadW(string targetName, uint type, uint flags, out IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree")]
    private static extern void CredFree(IntPtr credential);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CredDeleteW(string targetName, uint type, uint flags);
}
