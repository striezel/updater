/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Collections.Generic;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates of CMake.
    /// </summary>
    public class CMake : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for CMake class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(CMake).FullName);


        /// <summary>
        /// publisher name for signed executables of CMake
        /// </summary>
        private const string publisherX509 = "CN=\"Kitware, Inc.\", O=\"Kitware, Inc.\", L=Clifton Park, S=New York, C=US, SERIALNUMBER=2235734, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=New York, OID.1.3.6.1.4.1.311.60.2.1.3=US";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 3, 10, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public CMake(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "3.30.4";
            return new AvailableSoftware("CMake",
                version,
                "^CMake$",
                "^CMake$",
                new InstallInfoMsi(
                    "https://github.com/Kitware/CMake/releases/download/v" + version + "/cmake-" + version + "-windows-i386.msi",
                    HashAlgorithm.SHA256,
                    "8bed5f42883ff8047e75a7ec17b36aa687d8eadc3062540e0632c4894f4ff5e8",
                    signature,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://github.com/Kitware/CMake/releases/download/v" + version + "/cmake-" + version + "-windows-x86_64.msi",
                    HashAlgorithm.SHA256,
                    "a866fd9af4fba909b4a281d494878832d18e944958fab4e463c335f5d69533a7",
                    signature,
                    "/qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "cmake", "cmake-gui", "cpack", "ctest" };
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of CMake...");
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://github.com/Kitware/CMake/releases");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of CMake: " + ex.Message);
                return null;
            }

            // HTML text will contain links to releases like "https://github.com/Kitware/CMake/releases/tag/v3.19.4".
            var reVersion = new Regex("CMake/releases/tag/v([0-9]+\\.[0-9]+\\.[0-9])\"");
            var matchesVersion = reVersion.Matches(html);
            if (matchesVersion.Count == 0)
                return null;
            var versions = new List<Triple>(matchesVersion.Count);
            foreach (Match item in matchesVersion)
            {
                versions.Add(new Triple(item.Groups[1].Value));
            }
            versions.Sort();
            string currentVersion = versions[versions.Count - 1].full();

            // download checksum file, e.g. "https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-SHA-256.txt"
            string htmlCode;
            try
            {
                var task = client.GetStringAsync("https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-SHA-256.txt");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of CMake: " + ex.Message);
                return null;
            }

            // find SHA256 hash for 32-bit installer
            var reHash = new Regex("[a-f0-9]{64}  cmake.+windows\\-i386\\.msi");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash32Bit = matchHash.Value[..64];
            // find SHA256 hash for 64-bit installer
            reHash = new Regex("[a-f0-9]{64}  cmake.+windows\\-x86_64\\.msi");
            matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash64Bit = matchHash.Value[..64];
            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            // e.g. https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-win32-x86.msi (until 3.19.8)
            //   or https://github.com/Kitware/CMake/releases/download/v3.20.2/cmake-3.20.2-windows-i386.msi (since 3.20.0)
            newInfo.install32Bit.downloadUrl = "https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-windows-i386.msi";
            newInfo.install32Bit.checksum = newHash32Bit;
            // e.g. https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-win64-x64.msi (until 3.19.8)
            //   or https://github.com/Kitware/CMake/releases/download/v3.20.1/cmake-3.20.1-windows-x86_64.msi (since 3.20.0)
            newInfo.install64Bit.downloadUrl = "https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-windows-x86_64.msi";
            newInfo.install64Bit.checksum = newHash64Bit;
            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(3)
            {
                "cmake",
                "cmake-gui",
                "cpack",
                "ctest"
            };
        }
    } // class
} // namespace
