using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SshSpeedDownloader.Core;
using SshSpeedDownloader.Transport;
using SshSpeedDownloader.Transport.IdentityProviders;

var operation = args.FirstOrDefault() ?? "status";
var appRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MoDiDownloader");
var identityStore = new WindowsDeviceIdentityStore(Path.Combine(appRoot, "device-identity.json"), Environment.MachineName);
var device = await identityStore.LoadOrCreateAsync();
using var control = CloudDeviceAuthorizationClient.CreateHttpClient();
var options = new CloudDeviceAuthorizationOptions(new Uri("https://auth.modiconnect.cn/"),
    new ServerConnectionConfiguration("39.105.70.140", 22, "modi-relay", new[]
    {
        "SHA256:mlPaG+lfjBo92T/OG7fVrVz4sxY+rM+1hTxT+hY9X4k",
        "SHA256:FjMNC1WcRbxcpiNwiVzEauHETLOWagnixLgQtWoSNyk",
        "SHA256:rkxyIaeyapIwt1zGy+JPffafL8ClWOYRQIvkvuFiGls"
    }));
var cloud = new CloudDeviceAuthorizationClient(control, identityStore, options);
using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(4));
var token = deadline.Token;

if (operation == "request")
{
    var registration = await cloud.RegisterDeviceAsync(device, token);
    if (!registration.Succeeded) throw new InvalidOperationException(registration.UserMessage);
    var request = await cloud.RequestAccessAsync(device, token);
    Console.WriteLine(JsonSerializer.Serialize(new { device.DeviceId, device.DisplayName, request.Succeeded, request.Value, request.UserMessage }));
    return request.Succeeded ? 0 : 1;
}
if (operation == "status")
{
    var state = await cloud.GetCurrentAccessRequestAsync(device, token);
    Console.WriteLine(JsonSerializer.Serialize(new { device.DeviceId, state.Succeeded, state.Value, state.UserMessage }));
    return state.Succeeded ? 0 : 1;
}
var access = await cloud.AcquireConnectionIdentityAsync(device, token);
if (access.Identity is null) throw new InvalidOperationException(access.UserMessage ?? access.State.ToString());
await using var tunnels = new SshTunnelManager();
await tunnels.ConnectAsync(access.Identity.SshProfile, "", false, token);
using (var lease = tunnels.AcquireHttpClient())
{
    var trace = await lease.HttpClient.GetStringAsync("https://www.cloudflare.com/cdn-cgi/trace", token);
    var exitIp = trace.Split('\n').FirstOrDefault(line => line.StartsWith("ip=", StringComparison.Ordinal));
    Console.WriteLine(JsonSerializer.Serialize(new { tunnelCount = tunnels.TunnelCount, exitIp }));
    if (exitIp != "ip=39.105.70.140") throw new InvalidDataException("Unexpected cloud egress address.");
    if (operation == "verify")
    {
        foreach (var blocked in new[] { "http://127.0.0.1:17320/healthz", "http://39.105.70.140:22/", "http://100.100.100.200/latest/meta-data/", "http://10.0.0.1/", "http://[::1]/" })
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            try
            {
                using var response = await lease.HttpClient.GetAsync(blocked, timeout.Token);
                throw new InvalidDataException("A nonpublic relay destination was reachable.");
            }
            catch (Exception error) when (error is HttpRequestException or OperationCanceledException)
            {
                Console.WriteLine(JsonSerializer.Serialize(new { blockedDestination = new Uri(blocked).Host, blocked = true }));
            }
        }
        await using var boundary = await SshTunnelConnection.OpenAsync(access.Identity.SshProfile, "", token);
        try
        {
            await boundary.ReadServerIdentityAsync(token);
            throw new InvalidDataException("The restricted account unexpectedly permitted a shell command.");
        }
        catch (Renci.SshNet.Common.SshException)
        {
            Console.WriteLine("{\"shellDenied\":true}");
        }
        return 0;
    }
}
if (operation is not ("download" or "resume") || args.Length < 4) throw new ArgumentException("Usage: request | status | verify | download/resume URL concurrency output-directory [pause] [reconnect] [drop]");
var source = new Uri(args[1]);
var concurrency = int.Parse(args[2]);
var output = Path.GetFullPath(args[3]);
var manifestRoot = Path.Combine(output, "manifests");
var timer = Stopwatch.StartNew();
Guid taskId;
await using (var downloads = new DownloadManager(tunnels, new JsonDownloadManifestStore(manifestRoot)))
{
    if (operation == "resume")
    {
        await downloads.RestoreAsync(token);
        taskId = downloads.GetSnapshots().Single(task => task.Status != DownloadTaskStatus.Completed).Id;
        await downloads.ResumeAsync(taskId, token);
    }
    else
        taskId = await downloads.AddAsync(new DownloadRequest(source, output, concurrency, AutoTuneConcurrency: false));
    if (args.Contains("drop"))
    {
        while (downloads.GetSnapshot(taskId).ReceivedBytes < 1_048_576)
        {
            if (downloads.GetSnapshot(taskId).Status is DownloadTaskStatus.Completed or DownloadTaskStatus.Failed)
                throw new InvalidOperationException("Transfer ended before fault injection.");
            await Task.Delay(100, token);
        }
        // Verification-only fault injection closes this tool's TCP socket, not a shared server service.
        var connections = (IEnumerable<SshTunnelConnection>)typeof(SshTunnelManager)
            .GetField("_connections", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(tunnels)!;
        foreach (var connection in connections.ToArray())
        {
            var client = (Renci.SshNet.SshClient)typeof(SshTunnelConnection)
                .GetField("_client", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(connection)!;
            var session = typeof(Renci.SshNet.BaseClient)
                .GetProperty("Session", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(client)!;
            var socket = (System.Net.Sockets.Socket)session.GetType()
                .GetField("_socket", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!.GetValue(session)!;
            socket.Dispose();
        }
        Console.WriteLine("{\"injectedLocalSshDisconnect\":true}");
    }
    if (args.Contains("pause"))
    {
        while (downloads.GetSnapshot(taskId).ReceivedBytes < 1_048_576 && downloads.GetSnapshot(taskId).Status != DownloadTaskStatus.Completed)
            await Task.Delay(100, token);
        await downloads.PauseAsync(taskId);
        Console.WriteLine(JsonSerializer.Serialize(new { paused = downloads.GetSnapshot(taskId).Status.ToString(), savedBytes = downloads.GetSnapshot(taskId).ReceivedBytes }));
    }
    else
    {
        await Complete(downloads, taskId, token);
        return 0;
    }
}
if (args.Contains("reconnect"))
{
    await tunnels.DisconnectAsync();
    try
    {
        using var unavailable = tunnels.AcquireHttpClient();
        throw new InvalidDataException("A disconnected pool returned an HTTP client.");
    }
    catch (TunnelUnavailableException)
    {
        Console.WriteLine("{\"disconnectedPoolDenied\":true}");
    }
    await tunnels.ConnectAsync(access.Identity.SshProfile, "", false, token);
    Console.WriteLine("{\"tunnelReconnected\":true}");
}
await using (var restored = new DownloadManager(tunnels, new JsonDownloadManifestStore(manifestRoot)))
{
    await restored.RestoreAsync(token);
    await restored.ResumeAsync(taskId, token);
    await Complete(restored, taskId, token);
}
return 0;

async Task Complete(DownloadManager manager, Guid id, CancellationToken cancellationToken)
{
    while (true)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = manager.GetSnapshot(id);
        if (snapshot.Status == DownloadTaskStatus.Completed)
        {
            using var file = File.OpenRead(snapshot.TargetPath);
            var digest = Convert.ToHexString(await SHA256.HashDataAsync(file, cancellationToken));
            Console.WriteLine(JsonSerializer.Serialize(new { snapshot.TargetPath, snapshot.TotalBytes, snapshot.SupportsRanges, snapshot.RetryCount, snapshot.CompletedChunkCount, snapshot.TotalChunkCount, seconds = timer.Elapsed.TotalSeconds, mibPerSecond = snapshot.ReceivedBytes / 1048576d / timer.Elapsed.TotalSeconds, sha256 = digest }));
            return;
        }
        if (snapshot.Status is DownloadTaskStatus.Failed or DownloadTaskStatus.ResourceChanged)
            throw new InvalidOperationException(snapshot.Error);
        await Task.Delay(250, cancellationToken);
    }
}
