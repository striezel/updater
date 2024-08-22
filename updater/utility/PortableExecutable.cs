/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.IO;

namespace updater.utility
{
    /// <summary>
    /// eumeration type for Portable Executable formats (32 / 64-bit)
    /// </summary>
    public enum PEFormat
    {
        /// <summary>
        /// unknown format
        /// </summary>
        Unknown,

        /// <summary>
        /// not a portable executable file
        /// </summary>
        NotPE,

        /// <summary>
        /// 32-bit executable
        /// </summary>
        PE32,

        /// <summary>
        /// 64-bit executable
        /// </summary>
        PE64
    }


    /// <summary>
    /// Utility class to determine format of portable executables.
    /// </summary>
    public static class PortableExecutable
    {
        /// <summary>
        /// NLog.Logger for PortableExecutable class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(PortableExecutable).FullName);


        /// <summary>
        /// Determines the executable format of the given file.
        /// </summary>
        /// <param name="fileName">path and name of the executable file</param>
        /// <returns>Returns enumeration value to indicate the executable format.</returns>
        public static PEFormat determineFormat(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
                return PEFormat.NotPE;
            if (!File.Exists(fileName))
                return PEFormat.NotPE;

            ushort machineType = 0;

            try
            {
                //Inspired by http://stackoverflow.com/a/1002672

                // Offset to PE header is located at 0x3C.
                // The PE header starts with "PE\0\0" =  0x50 0x45 0x00 0x00,
                // followed by a 2-byte machine type field.
                var fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
                try
                {
                    var br = new BinaryReader(fs);
                    try
                    {
                        fs.Seek(0x3c, SeekOrigin.Begin);
                        int peOffset = br.ReadInt32();
                        fs.Seek(peOffset, SeekOrigin.Begin);
                        uint peHead = br.ReadUInt32();

                        if (peHead != 0x00004550) // "PE\0\0", little-endian
                            return PEFormat.NotPE;
                        // read machine type field
                        machineType = br.ReadUInt16();
                    } // try-fin
                    finally
                    {
                        br.Close();
                        br = null;
                    }
                } // try-fin
                finally
                {
                    fs.Close();
                    fs = null;
                }
            } // try-catch
            catch (Exception ex)
            {
                logger.Error("Error (" + ex.GetType().Name + ") while determining executable type of \""
                    + fileName + "\": " + ex.Message);
                return PEFormat.NotPE;
            }

            switch (machineType)
            {
                case 0:
                    return PEFormat.Unknown;
                case 0x8664: // AMD 64
                case 0x200: // Itanium 64
                    return PEFormat.PE64;
                case 0x14c: // i386
                    return PEFormat.PE32;
                default:
                    return PEFormat.Unknown;
            }
        }

    } // class
} // namespace
