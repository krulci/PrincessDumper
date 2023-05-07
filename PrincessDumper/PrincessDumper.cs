using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PrincessDumper
{
    public class PrincessDumper
    {
        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        public static void RuntimeDump(BepInEx.Logging.ManualLogSource logger, out byte[] il2cppBytes, out byte[] metadataBytes)
        {
            string moduleName = "GameAssembly.dll";
            Process process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] moduleBytes = new byte[module.ModuleMemorySize];
                    IntPtr bytesRead;
                    if (!ReadProcessMemory(process.Handle, module.BaseAddress, moduleBytes, module.ModuleMemorySize, out bytesRead))
                    {
                        logger.LogError("Failed to read process memory");
                        il2cppBytes = Array.Empty<byte>();
                        metadataBytes = Array.Empty<byte>();
                        return;
                    }
                    using (var stream = new MemoryStream(moduleBytes))
                    using (var reader = new BinaryReader(stream))
                    using (var writer = new BinaryWriter(stream))
                    {
                        // Parse the PE header to get the section headers
                        stream.Position = 0x3C;
                        int peHeaderOffset = reader.ReadInt32();
                        logger.LogInfo($"peHeaderOffset: {peHeaderOffset}");
                        stream.Position = peHeaderOffset + 6;
                        ushort numberOfSections = reader.ReadUInt16();
                        uint timeDateStame = reader.ReadUInt32();
                        uint pointerToSymbolTable = reader.ReadUInt32();
                        uint numberOfSymbols = reader.ReadUInt32();
                        ushort sizeOfOptionalHeader = reader.ReadUInt16();
                        ushort characteristics = reader.ReadUInt16();
                        int section0StartPosition = (int)stream.Position + sizeOfOptionalHeader;

                        // Update each section header's PointerToRawData and SizeOfRawData fields
                        for (int i = 0; i < numberOfSections; i++)
                        {
                            logger.LogInfo($"numberOfSections: {numberOfSections}");
                            stream.Position = section0StartPosition + (i * 40);
                            logger.LogInfo(stream.Position);
                            byte[] sectionNameBytes = reader.ReadBytes(8);
                            string sectionName = Encoding.ASCII.GetString(sectionNameBytes).TrimEnd('\0');
                            logger.LogInfo(sectionName);
                            uint virtualSize = reader.ReadUInt32();
                            logger.LogInfo($"VirtualSize: {virtualSize:X}" + $" stream.Position: {stream.Position}");
                            uint virtualAddress = reader.ReadUInt32();
                            logger.LogInfo($"VirtualAddress: {virtualAddress:X}" + $" stream.Position: {stream.Position}");
                            writer.Write(virtualSize);
                            logger.LogInfo($"Replacing SizeOfRawData with VirtualSize value of {virtualSize:X}" + $" stream.Position: {stream.Position}");
                            writer.Write(virtualAddress);
                            logger.LogInfo($"Replacing SizeOfRawData with VirtualSize value of {virtualAddress:X}" + $" stream.Position: {stream.Position}");
                        }
                    }
                    /*using (FileStream stream = new FileStream("GameAssembly_dump.dll", FileMode.Create, FileAccess.Write))
                    {
                        stream.Write(moduleBytes, 0, moduleBytes.Length);
                    }*/
                    logger.LogInfo(string.Format("Processed {0}", moduleName));
                    il2cppBytes = moduleBytes;

                    byte[] byteArray = moduleBytes;

                    // convert pattern to byte array
                    byte[] pattern = { 0xAF, 0x1B, 0xB1, 0xFA };

                    // search for pattern in the byte array
                    int index = Array.IndexOf(byteArray, pattern[0]);
                    while (index >= 0 && index <= byteArray.Length - pattern.Length)
                    {
                        if (byteArray.Skip(index).Take(pattern.Length).SequenceEqual(pattern))
                        {
                            // pattern found, trim everything before it
                            byte[] trimmedArray = new byte[byteArray.Length - index];
                            Array.Copy(byteArray, index, trimmedArray, 0, trimmedArray.Length);
                            byteArray = trimmedArray;
                            break;
                        }
                        index = Array.IndexOf(byteArray, pattern[0], index + 1);
                    }
                    /*using (FileStream stream = new FileStream("global-metadata.dat", FileMode.Create, FileAccess.Write))
                    {
                        stream.Write(byteArray, 0, byteArray.Length);
                    }*/
                    logger.LogInfo(string.Format("Processed {0}", "global-metadata.dat"));
                    metadataBytes = byteArray;
                    return;
                }
            }
            logger.LogError(string.Format("{0} not found", moduleName));
            il2cppBytes = Array.Empty<byte>();
            metadataBytes = Array.Empty<byte>();
            return;
        }
    }
}