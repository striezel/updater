/*
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of CMake.
    /// </summary>
    public class CMake: NoPreUpdateProcessSoftware
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
            const string version = "3.19.6";
            return new AvailableSoftware("CMake",
                version,
                "^CMake$",
                "^CMake$",
                new InstallInfoMsi(
                    "https://github.com/Kitware/CMake/releases/download/v"+ version + "/cmake-" + version + "-win32-x86.msi",
                    HashAlgorithm.SHA256,
                    "860768c5f71e747164d4fe22e041aea17f4aece3248ad56a881e982dc253ca97",
                    publisherX509,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://github.com/Kitware/CMake/releases/download/v" + version + "/cmake-" + version + "-win64-x64.msi",
                    HashAlgorithm.SHA256,
                    "c3d48a91dc1637e7fd832620ae6de8c252f71d4d3f3013f935cb018e14fc7a45",
                    publisherX509,
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
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of CMake...");
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://github.com/Kitware/CMake/releases/latest");
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            string currentVersion;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                // Location header will point to something like "https://github.com/Kitware/CMake/releases/tag/v3.19.4".
                Regex reVersion = new Regex("v[0-9]+\\.[0-9]+\\.[0-9]$");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                currentVersion = matchVersion.Value.Remove(0, 1);
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of CMake: " + ex.Message);
                return null;
            }

            // download checksum file, e.g. "https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-SHA-256.txt"
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-SHA-256.txt");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of CMake: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // find SHA256 hash for 32 bit installer
            Regex reHash = new Regex("[a-f0-9]{64}  cmake.+win32\\-x86\\.msi");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash32Bit = matchHash.Value.Substring(0, 64);
            // find SHA256 hash for 64 bit installer
            reHash = new Regex("[a-f0-9]{64}  cmake.+win64\\-x64\\.msi");
            matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash64Bit = matchHash.Value.Substring(0, 64);
            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            // e. g. https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-win32-x86.msi
            newInfo.install32Bit.downloadUrl = "https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-win32-x86.msi";
            newInfo.install32Bit.checksum = newHash32Bit;
            // e. g. https://github.com/Kitware/CMake/releases/download/v3.19.4/cmake-3.19.4-win64-x64.msi
            newInfo.install64Bit.downloadUrl = "https://github.com/Kitware/CMake/releases/download/v" + currentVersion + "/cmake-" + currentVersion + "-win64-x64.msi";
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
            return new List<string>(1)
            {
                "cmake"
            };
        }
    } // class
} // namespace
