---
title: 利用符号链接进行dll劫持
date: 2022-02-12 16:43:36
tags:
---

# 利用符号链接进行DLL劫持



## DefineDosDevice 利用

James Forshaw发现的技术依赖于API函数DefineDosDevice的使用，并涉及一些不容易掌握的Windows内部知识。

### DefineDosDevice

这里是 "DefineDosDevice "函数的原型

```c++
BOOL DefineDosDeviceW(
  DWORD   dwFlags,
  LPCWSTR lpDeviceName,
  LPCWSTR lpTargetPath
);
```

正如它的名字所暗示的，DefineDosDevice的目的是定义MS-DOS设备名称。一个MS-DOS设备名称是对象管理器中的一个符号链接，其名称的形式为\DosDevices\DEVICE_NAME（例如：\DosDevices\C:），这个函数允许你把一个实际的 "设备 "映射到一个 "DOS设备"。例如，当你插入一个外部驱动器或USB时，该设备会被自动分配一个盘符，例如E：。你可以通过调用QueryDosDevice获得相应的映射。

```c++
WCHAR path[MAX_PATH + 1];

if (QueryDosDevice(argv[1], path, MAX_PATH)) {
    wprintf(L"%ws -> %ws\n", argv[1], path);
}
```

![image-20220212102119030](/_img/image-20220212102119030.png)

在上面的例子中，目标设备是\Device\HarddiskVolume3，MS-DOS设备名称是C:。但等一下，我说过MS-DOS设备名称的形式是\DosDevices\DEVICE_NAME。所以，这不可能只是一个盘符。不用担心，这里有一个解释。对于DefineDosDevice和QueryDosDevice来说，\DosDevices/部分是隐含的。这些函数会自动在 "设备名称 "前加上"??"。所以，如果你提供C:作为设备名称，它们会在内部使用NT路径\??\C:。即使这样，你会告诉我， \??\仍然不是 \DosDevices\，这将是一个有效的观点。再次，WinObj将帮助我们解开这个 "谜"。在对象管理器的根目录中，我们可以看到，\DosDevices只是一个符号链接，它指向了 \?? 因此，\DosDevices\C:-> \??\C:，所以我们可以把它们看作是同一事物。这个符号链接的存在实际上是出于传统的原因，因为在旧版本的Windows中，只有一个DOS设备目录。

![image-20220212102021967](/_img/image-20220212102021967.png)

路径前缀 \??\本身有非常特殊的含义。它代表一个用户的本地DOS设备目录，因此根据当前用户的上下文，它指的是对象管理器中的不同位置。具体来说，"? "指的是完整的路径\Sessions\0\DosDevices\00000000-XXXXXX，其中XXXXXXX是用户的登录认证ID。但有一个例外，对于NT AUTHORITY/SYSTEM， \??是指 \GLOBAL??。

挂载一个磁盘，驱动器是以登录用户的身份挂载的，所以\??应该指的是 \Sessions\0\DosDevices\00000000-XXXXXX，但XXXXXXX的值是什么？为了找到它，我将使用Process Hacker并检查我的explorer.exe进程的Token的Advanced。

![image-20220212112053074](/_img/image-20220212112053074.png)

![image-20220212112253601](/_img/image-20220212112253601.png)





设备映射操作包括在调用者的DOS设备目录中创建一个简单的符号链接。任何用户都可以这样做，因为这只影响到他们的会话。但是有一个问题，因为低权限的用户只能创建 "临时 "内核对象，一旦所有的句柄被关闭，这些对象就会被删除。为了解决这个问题，必须将对象标记为 "永久"，但这需要一个特殊的权限（SeCreatePermanentPrivilege），而他们并不具备这个权限。所以，这个操作必须由一个具有这种能力的特权服务来执行。

![image-20220212112730238](/_img/image-20220212112730238.png)



DefineDosDevice是一个RPC方法调用的包装。这个方法是由CSRSS服务公开的，在BASESRV.DLL中的BaseSrvDefineDosDevice中实现。这个服务的特殊之处在于它以保护级别WinTcb的PPL方式运行。

尽管这对我们的攻击来说是一个要求，但这并不是DefineDosDevice最有趣的事实。更有趣的是，lpDeviceName的值没有被净化。这意味着你不一定要提供一个驱动器的字母，如C：。我们将看到我们如何利用这一点来欺骗CSRSS服务在一个任意的位置创建一个任意的符号链接，如\KnownDlls

### DefineDosDevice 利用

 这里由scrt提供了BaseSrvDefineDosDevice方法的流程图

![image-20220212133932879](/_img/image-20220212133932879.png)

蓝色方框代表了创建符号链接，红色方框代表关键路径，橙色方框代表impersonation（冒充）功能

首先，我们可以看到CSRSS服务试图打开\??\DEVICE_NAME，同时冒充调用者（即RPC客户端）。主要目的是先删除符号链接，如果它已经存在。但还有一点，该服务还将检查该符号链接是否是 "global "的。为此，一个内部函数简单地检查对象的 "real "路径是否以 \GLOBAL??\ 开始。如果是的话，在剩下的执行过程中，冒充被禁用，在NtCreateSymbolicLinkObject()调用之前，服务将不会冒充客户端，这意味着符号链接将由CSRSS服务自己创建。最后，如果这个操作成功了，服务就会把这个对象标记为 "permanent"。

在这一点上，你可能已经意识到存在一个条件竞争（Time-of-Check Time-of-Use）漏洞，用来打开符号链接的路径和用来创建符号链接的路径都是：	\??\DEVICE_NAME。然而，"open "操作总是在冒充用户时进行的，而 "create "操作可能在冒充功能被禁用的情况下直接作为SYSTEM进行。

按照之前的一个解释，\??代表一个用户的本地dos设备目录，因此根据用户的身份，可以解析到不同的路径。因此，尽管在这两种情况下使用的是同一个路径，但在现实中它很可能指的是完全不同的位置!

为了利用这种行为，我们必须解决以下问题：我们需要找到一个 "device name"，当服务冒充客户时，它可以解析到我们控制的 "global object"。而这个同样的 "device name"必须在禁止冒充时解析为\KnownDlls\FOO.dll。

我们需要在 \??\DEVICE_NAME中确定一个值，使这个路径在调用者为SYSTEM时解析为 \KnownDlls\FOO.dll。我们还知道，在这种情况下， \??解析为 \GLOBAL??。

利用winobj去查看\GLOBAL??的内容时，可以发现有一个对象叫做GLOBALROOT。

![image-20220212135432649](/_img/image-20220212135432649.png)

在这个目录中，GLOBALROOT对象是一个符号链接，指向一个空路径。这意味着诸如 \??\GLOBALROOT\这样的路径将转化为只有 \，它是对象管理器的根（因此被称为 "GLOBALROOT"）。如果我们将这一原则应用于我们的 "device name"，我们知道，当调用者为SYSTEM时，\GLOBALROOT\KnownDlls\FOO.dll将解析为\KnownDlls\FOO.dll。

现在，我们知道我们应该提供GLOBALROOT\KnownDlls\FOO.dll作为DefineDosDevice函数调用的 "device name"（\??\将自动预加到这个值上）。如果我们想让CSRSS服务禁用冒充，我们也知道符号链接对象必须被视为 "global"，所以它的路径必须以\GLOBAL??\开始。因此，问题是：你如何将\??\GLOBALROOT\KnownDlls\FOO.dll的路径转化为\GLOBAL??\KnownDlls\FOO.dll，解决方案实际上是非常直接的，因为这几乎是符号链接的定义! 当服务冒充用户时，我们知道 \? 指的是这个特定用户的本地DOS设备目录，所以你所要做的就是创建一个符号链接，使 \??\GLOBALROOT指向 \GLOBAL??。

当路径被SYSTEM以外的用户打开时:

```
\??\GLOBALROOT\KnownDlls\FOO.dll
-> \Sessions\0\DosDevices\00000000-XXXXXXXX\GLOBALROOT\KnownDlls\FOO.dll

\Sessions\0\DosDevices\00000000-XXXXXXXX\GLOBALROOT\KnownDlls\FOO.dll
-> \GLOBAL??\KnownDlls\FOO.dll
```

另一方面，如果同一路径被SYSTEM打开时:

```
\??\GLOBALROOT\KnownDlls\FOO.dll
-> \GLOBAL??\GLOBALROOT\KnownDlls\FOO.dll

\GLOBAL??\GLOBALROOT\KnownDlls\FOO.dll
-> \KnownDlls\FOO.dll
```

在检查对象是否是 "global "之前，它首先必须存在，否则最初的 "open "操作就会失败。所以，在调用DefineDosDevice之前，我们需要确保\GLOBAL??\KnownDlls\FOO.dll是一个现有的符号链接对象。首先在 \GLOBAL??内创建一个假的KnownDlls目录，然后在其中创建一个假的符号链接对象，名称为我们想要劫持的DLL。

### 整理利用思路

1、提升权限保证能在 \GLOBAL??内创建对象，创建对象目录\GLOBAL??\KnownDlls来模仿实际的\KnownDlls目录。

2、创建符号链接 \GLOBAL??\KnownDlls\FOO.dll，其中FOO.dll是我们要劫持的DLL的名称。记住，重要的是链接本身的名称，而不是其目标。

3、在当前用户的DOS设备目录下创建一个名为GLOBALROOT的符号链接，并指向\GLOBAL??。这一步不能以SYSTEM的身份进行，因为我们要在自己的DOS目录中创建一个假的GLOBALROOT链接。

4、调用DefineDosDevice，以GLOBALROOT\KnownDlls\FOO.dll为设备名。这个设备的目标路径是DLL的位置。

```
\??\GLOBALROOT\KnownDlls\FOO.dll
-> \Sessions\0\DosDevices\00000000-XXXXXXXX\GLOBALROOT\KnownDlls\FOO.dll
-> \GLOBAL??\KnownDlls\FOO.dll
```

既然这个对象存在，它就会检查它是否是全局的。正如你所看到的，该对象的 "真实 "路径以\GLOBAL??\开始，所以它确实被认为是全局的，并且在剩下的执行过程中禁止冒充。当前的链接被删除，一个新的链接被创建，但是这一次，RPC客户端没有被冒充，所以这个操作是在CSRSS服务本身的上下文中完成的，即SYSTEM:

```
\??\GLOBALROOT\KnownDlls\FOO.dll
-> \GLOBAL??\GLOBALROOT\KnownDlls\FOO.dll
-> \KnownDlls\FOO.dll
```

现在我们知道了如何在\KnownDlls目录中添加任意一个目录。

该方法需要修改\global??比较难以利用，然后XPN根据该方法提出了一个更为优秀的利用思路

## object overload利用

在scrt的方式上又有了新的一个利用方式，该方式不用修改Global??，直接修改进程内部的dosdevice。

### 创建符号链接

首先，了解一下创建符号链接。我们怎样才能在对象管理器中创建我们自己的符号链接呢？正如你所期望的那样，我们在创建方式和地点方面受到一些限制。一般来说，用户有权限在几个地方创建新的对象，包括如下位置。

- \RPC Control
- \Sessions\0\DosDevices\00000000-[LUID]

利用NtObjectManager来创建一个新的符号链接

![image-20220212143924784](/_img/image-20220212143924784.png)

![image-20220212143948345](/_img/image-20220212143948345.png)

如果我们用$h.Close()关闭我们新的符号链接的句柄，我们会发现符号链接很快就消失，我们还能用符号链接做什么？我们分配一个新的驱动器。

```powershell
$h = New-NtSymbolicLink -Access GenericAll -Path "\??\p:" -TargetPath "\Device\HardDiskVolume3"
```

![image-20220212144351821](/_img/image-20220212144351821.png)

### 利用分析

我们可以在对象管理器中为我们用户的会话重载现有的对象，但对以我们当前用户身份运行的所有进程这样做肯定会引起一些问题。值得庆幸的是，我们实际上可以在每个进程的基础上这样做。

如果我们看一下ntdll调用NtSetInformationProcess，在SDK的深处，我们发现一个ProcessDeviceMap的选项，它被用来为一个进程分配一个新的DosDevices对象目录

利用XPN给出代码来进行poc测试，首先利用poc注入一个我们生成的进程，可以看到我们进程的DosDevices已经被修改为\??\pretest\指向的地址为\Device\HardDiskVolume3\test也就是原本我们的C:\test目录。

![image-20220212152214155](/_img/image-20220212152214155.png)

我们对如何调整一个进程在操作系统上的对象的看法的认识，我们怎样才能利用这一点将任意的代码加载到一个进程中呢？最明显的方法是生成一个进程，并让它加载一个我们控制的DLL。

XPN提出了一个例子，劫持windows defender。找到一个在启动时被进程加载的DLL。需要从磁盘上实际加载的第一个DLL，而不是KnownDlls中的一个部分，XPN选择利用mason1.dll

![image-20220212155033648](/_img/image-20220212155033648.png)

由于我们正在劫持一个DLL，通常我们需要实现与MSASN1.dll相同的导入，或者面临STATUS_INVALID_IMAGE_FORMAT错误。然而在这种情况下，MSASN1.dll是从wintrust.dll中延迟加载的，而wintrust.dll是存储在KnownDLLs中。

这意味着我们的恶意DLL直到第一个函数被调用时才被加载，此时应用程序已经从KnownDLLs中加载了它的DLLs。具有讽刺意味的是，这使我们在这个最初的例子中生活得更轻松，因为加载器将只使用LoadLibrary和GetProcAddress。

首先我们在创建一个C:\test\Windows\System32目录，将一个恶意的dll命名为mason1.dll放入目录。

```
CreateProcessA(NULL, (LPSTR)"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2201.10-0\\MsMpEng.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
```

创建一个进程并停止他，然后利用NtSetInformationProcess修改C:的符号链接。

```
status = pNtSetInformationProcess(pi.hProcess, ProcessDeviceMap, &dirHandle, sizeof(dirHandle));
if (status != 0) {
    printf("[!] Error setting ProcessDeviceMap\n");
    return 2;
}
```

然后利用resumethread来恢复线程。

然而在实际测试中发现，可能是由于版本的区别，defender并没有去我们设置的目录加载MSASN1.dll，反而是去加载了version.dll

![image-20220212162318589](/_img/image-20220212162318589.png)

可能是由于版本问题导致的，mason1.dll在Knowdlls内，这里修改为version.dll再重新进行测试。

![image-20220212163412602](/_img/image-20220212163412602.png)

![image-20220212161713020](/_img/image-20220212161713020.png)

相对应的，该方法需要知道msmpeng.exe的路径，xpn又提出了利用defrag.exe来进行dll劫持。

![image-20220212163049828](/_img/image-20220212163049828.png)

如果我们看一下导入的库，我们会发现除了sxshared.dll之外，所有的库都存在于KnownDLLs中。这意味着我们可以劫持 sxshared.dll，但由于这是由加载器初始化的，我们将模拟出导出的函数。使用SharpDllProxy这样的工具，我们可以生成一组转发导出函数，并将其扔进我们的DLL中。

### 远程加载DLL

们现在知道如何将我们的DLL加载到进程中，但是我们要加载的DLL需要存储在哪里呢？由于我们现在只是利用符号链接，所以没有什么可以阻止我们从网络上加载DLL。可以通过将你的符号链接指向以下位置：

```
\Device\LanmanRedirector\networkserver\shared
```

![image-20220212163716100](/_img/image-20220212163716100.png)



## 参考链接

[Bypassing LSA Protection in Userland – Sec Team Blog (scrt.ch)](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/)

[Object Overloading - TrustedSec](https://www.trustedsec.com/blog/object-overloading/)

[xpn/ObjectOverloadingPOC (github.com)](https://github.com/xpn/ObjectOverloadingPOC)
