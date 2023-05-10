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
        private static ManualLogSource logger { get; set; }

        /// <summary>
        /// Initializes the ExtensionMethods class.
        /// </summary>
        static PrincessDumper()
        {
            logger = new ManualLogSource("PrincessDumper");
            Logger.Sources.Add(logger);
        }

        [DllImport("kernel32.dll")]
        internal static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

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
                logger.LogWarning("global-metadata.dat is not embedded in GameAssembly.dll.");
                if (File.Exists(metadataPath))
                {
                    logger.LogWarning("Found global-metadata.dat at the default path, using it instead.");
                    metadataBytes = File.ReadAllBytes(metadataPath);
                }
                else
                {
                    logger.LogWarning("global-meatadata.dat is not found at the default location. " +
                        "It may be hidden somewhere else. " +
                        "\n Input the file path: (Example: C:\\Users\\_\\{YourGame}\\fake-global-metadata-name.fakeExtension");
                    metadataPath = Path.Combine(Console.ReadLine());
                    metadataBytes = File.ReadAllBytes(metadataPath);
                }
            }
        }
    }
}
