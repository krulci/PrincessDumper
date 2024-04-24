using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using BepInEx.Logging;

namespace PrincessDumper
{
    /// <summary>
    /// Provides functionality for runtime dumping of a specified module's memory, including IL2CPP bytes and metadata bytes.
    /// </summary>
    public class PrincessDumper
    {
        /// <summary>
        /// The logger used for logging information and errors.
        /// </summary>
        private static ManualLogSource Logger { get; set; }

        /// <summary>
        /// Initializes the ExtensionMethods class.
        /// </summary>
        static PrincessDumper()
        {
            Logger = new ManualLogSource("PrincessDumper");
            BepInEx.Logging.Logger.Sources.Add(Logger);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        // Import the VirtualQueryEx function from kernel32.dll
        [DllImport("kernel32.dll")]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        // Define the MEMORY_BASIC_INFORMATION structure
        [StructLayout(LayoutKind.Sequential)]
        internal struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        /// <summary>
        /// Performs a runtime dump of the specified module's memory and retrieves IL2CPP bytes and metadata bytes.
        /// </summary>
        /// <param name="il2cppBytes">Output parameter to store the IL2CPP bytes.</param>
        /// <param name="metadataBytes">Output parameter to store the metadata bytes.</param>
        public static void RuntimeDump(out byte[] il2cppBytes, out byte[] metadataBytes)
        {
            string moduleName = "GameAssembly.dll";
            Process process = Process.GetCurrentProcess();
            foreach (ProcessModule module in process.Modules)
            {
                if (module.ModuleName is null)
                {
                    break;
                }
                if (module.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                {
                    byte[] moduleBytes = new byte[module.ModuleMemorySize];
                    IntPtr moduleEndAddress = (IntPtr)((long)module.BaseAddress + (long)module.ModuleMemorySize);
                    IntPtr currentAddress = module.BaseAddress;
                    while (currentAddress.ToInt64() < moduleEndAddress.ToInt64())
                    {
                        int result = VirtualQueryEx(process.Handle, currentAddress, out MEMORY_BASIC_INFORMATION memoryInfo, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION)));
                        if (result == 0)
                        {
                            // Error occurred or reached the end of the module's memory space
                            break;
                        }

                        byte[] buffer = new byte[(int)memoryInfo.RegionSize];
                        // Read memory contents
                        if (ReadProcessMemory(process.Handle, memoryInfo.BaseAddress, buffer, buffer.Length, out _))
                        {
                            // Dump the contents of buffer to a file or process it as needed
                            // Example: File.WriteAllBytes("dump.bin", buffer);
                            Buffer.BlockCopy(buffer, 0, moduleBytes, (int)(currentAddress.ToInt64() - module.BaseAddress.ToInt64()), buffer.Length);
                        }
                        else
                        {
                            // Failed to read memory
                            Logger.LogError("Failed to read memory at address: " + memoryInfo.BaseAddress);
                        }

                        // Move to the next memory region
                        currentAddress = (IntPtr)((long)memoryInfo.BaseAddress + (long)memoryInfo.RegionSize);
                    }
                    using (var stream = new MemoryStream(moduleBytes))
                    using (var reader = new BinaryReader(stream))
                    using (var writer = new BinaryWriter(stream))
                    {
                        // Parse the PE header to get the section headers
                        stream.Position = 0x3C;
                        int peHeaderOffset = reader.ReadInt32();
                        Logger.LogInfo($"peHeaderOffset: {peHeaderOffset}");
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
                            Logger.LogInfo($"numberOfSections: {numberOfSections}");
                            stream.Position = section0StartPosition + (i * 40);
                            Logger.LogInfo(stream.Position);
                            byte[] sectionNameBytes = reader.ReadBytes(8);
                            string sectionName = Encoding.ASCII.GetString(sectionNameBytes).TrimEnd('\0');
                            Logger.LogInfo(sectionName);
                            uint virtualSize = reader.ReadUInt32();
                            Logger.LogInfo($"VirtualSize: {virtualSize:X}" + $" stream.Position: {stream.Position}");
                            uint virtualAddress = reader.ReadUInt32();
                            Logger.LogInfo($"VirtualAddress: {virtualAddress:X}" + $" stream.Position: {stream.Position}");
                            writer.Write(virtualSize);
                            Logger.LogInfo($"Replacing SizeOfRawData with VirtualSize value of {virtualSize:X}" + $" stream.Position: {stream.Position}");
                            writer.Write(virtualAddress);
                            Logger.LogInfo($"Replacing SizeOfRawData with VirtualSize value of {virtualAddress:X}" + $" stream.Position: {stream.Position}");
                        }
                    }

                    Logger.LogInfo(string.Format("Processed {0}", moduleName));
                    il2cppBytes = moduleBytes;

                    byte[] byteArray = moduleBytes;

                    // convert pattern to byte array
                    byte[] pattern1 = { 0xAD, 0x3F, 0x20, 0xBB, 0x30, 0x30, 0xFA, 0x4A };
                    byte[] pattern2 = { 0xAF, 0x1B, 0xB1, 0xFA, 0x1D, 0x00, 0x00, 0x00 };

                    // search for pattern in the byte array
                    int index = Array.IndexOf(byteArray, pattern1[0]);
                    while (index >= 0 && index <= byteArray.Length - pattern1.Length)
                    {
                        if (byteArray.Skip(index).Take(pattern1.Length).SequenceEqual(pattern1))
                        {
                            // pattern found, trim everything before it
                            byte[] trimmedArray = new byte[byteArray.Length - index];
                            Array.Copy(pattern2, 0, trimmedArray, 0, pattern2.Length);
                            Array.Copy(byteArray, index + pattern1.Length, trimmedArray, pattern2.Length, trimmedArray.Length - pattern2.Length);

                            byteArray = trimmedArray;
                            break;
                        }
                        index = Array.IndexOf(byteArray, pattern1[0], index + 1);
                    }

                    Logger.LogInfo(string.Format("Processed {0}", "global-metadata.dat"));
                    metadataBytes = byteArray;
                    return;
                }
            }
            Logger.LogError(string.Format("{0} not found", moduleName));
            il2cppBytes = Array.Empty<byte>();
            metadataBytes = Array.Empty<byte>();
            return;
        }

        /// <summary>
        /// Validates the metadata by checking if the IL2CPP bytes and metadata bytes are the same.
        /// If they are the same, it searches for the global-metadata.dat file at the specified path
        /// and updates the metadata bytes accordingly. If the file is not found, it prompts the user
        /// to input the file path manually.
        /// </summary>
        /// <param name="metadataPath">The path to the global-metadata.dat file.</param>
        /// <param name="il2cppBytes">The IL2CPP file bytes.</param>
        /// <param name="metadataBytes">The metadata file bytes.</param>
        public static void ValidateMetadata(string metadataPath, byte[] il2cppBytes, ref byte[] metadataBytes)
        {
            //metadataBytes will equal il2cppBytes if the search pattern did not match.
            //In this case, global-metadata.dat is not embedded in GameAssembly.dll and most likely at the default path.
            if (il2cppBytes == metadataBytes)
            {
                Logger.LogWarning("global-metadata.dat is not embedded in GameAssembly.dll.");
                if (File.Exists(metadataPath))
                {
                    Logger.LogWarning("Found global-metadata.dat at the default path, using it instead.");
                    metadataBytes = File.ReadAllBytes(metadataPath);
                }
                else
                {
                    Logger.LogWarning("global-meatadata.dat is not found at the default location. " +
                        "It may be hidden somewhere else. " +
                        "\n Input the file path: (Example: C:\\Users\\_\\{YourGame}\\fake-global-metadata-name.fakeExtension");
                    metadataPath = Path.Combine(Console.ReadLine() ?? string.Empty);
                    metadataBytes = File.ReadAllBytes(metadataPath);
                }
            }
        }
    }
}
