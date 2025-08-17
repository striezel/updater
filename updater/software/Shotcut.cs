﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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

using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Shotcut video editor.
    /// </summary>
    public class Shotcut : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Shotcut class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Shotcut).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=\"Meltytech, LLC\", O=\"Meltytech, LLC\", L=Oceanside, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 5, 6, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public Shotcut(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            // Since v20.10.31, Shotcut only provides 64-bit builds on Windows.
            // Older 32-bit builds may still be installed, so we use the 64-bit build for
            // both 32-bit and 64-bit installations, effectively crossgrading 32-bit to
            // 64-bit installations.
            // To avoid any conflicts on older 32-bit OSes, the known info for the last
            // 32-bit build is returned in those cases.
            if (!Environment.Is64BitOperatingSystem)
                return last32BitBuildInformation();

            var signature = new Signature(publisherX509, certificateExpiration);
            var info = new InstallInfoExe(
                "https://github.com/mltframework/shotcut/releases/download/v25.08.16/shotcut-win64-250816.exe",
                HashAlgorithm.SHA256,
                "f59a037ecb9f0ffb65c8f5d4c34611fa9e35016e53118e79e1c4380ff9ef3659",
                signature,
                "/VERYSILENT /ALLUSERS /NORESTART");
            return new AvailableSoftware("Shotcut",
                "25.08.16",
                "^Shotcut$",
                "^Shotcut$",
                info,
                info);
        }


        /// <summary>
        /// Provides information for the last Shotcut version that still provided a 32-bit build.
        /// </summary>
        /// <returns>Returns information about the last available 32-bit build version.</returns>
        private static AvailableSoftware last32BitBuildInformation()
        {
            return new AvailableSoftware("Shotcut",
                "21.05.18",
                "^Shotcut$",
                "^Shotcut$",
                new InstallInfoExe(
                    "https://github.com/mltframework/shotcut/releases/download/v20.09.27/shotcut-win32-200927.exe",
                    HashAlgorithm.SHA256,
                    "8150459671a739fde8cb3e2bcbd6f4421f17f35ff20bf784850964872b2a110f",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://github.com/mltframework/shotcut/releases/download/v20.09.27/shotcut-win64-200927.exe",
                    HashAlgorithm.SHA256,
                    "83e954bbe91905820391e4cf91de14c39464e01ad56c34de7088bb11175ebae9",
                    Signature.None,
                    "/S"));
        }

        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["shotcut"];
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
        /// Determines the latest available version of Shotcut on GitHub.
        /// </summary>
        /// <returns>Returns the latest version in case of success.
        /// Return null, if an error occurred.</returns>
        private static string GetLatestVersion()
        {
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            string latestVersion;
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, "https://github.com/mltframework/shotcut/releases/latest"));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("tag/v[0-9]+\\.[0-9]+\\.[0-9]+$");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                latestVersion = matchVersion.Value[5..];
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Shotcut version: " + ex.Message);
                return null;
            }
            client.Dispose();
            return latestVersion;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Shotcut...");
            // Handle 32-bit OSes.
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Warning: Shotcut developers discontinued the 32-bit builds after version v20.09.27. "
                    + "If you want a more recent version of Shotcut, switch to a 64-bit operating system.");
                return last32BitBuildInformation();
            }

            // Get newest information (64-bit builds only).
            string currentVersion = GetLatestVersion();
            if (string.IsNullOrWhiteSpace(currentVersion))
                return null;

            // Get checksum from release page, e.g. "https://github.com/mltframework/shotcut/releases/download/v21.05.18/sha256sums.txt"
            string htmlCode = null;
            using (var client = new HttpClient() { Timeout = TimeSpan.FromSeconds(25) })
            {
                try
                {
                    var task = client.GetStringAsync("https://github.com/mltframework/shotcut/releases/download/v" + currentVersion + "/sha256sums.txt");
                    task.Wait();
                    htmlCode = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while retrieving checksums for newer version of Shotcut: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // find SHA256 hash for 64-bit installer
            var reHash = new Regex("[a-f0-9]{64}  shotcut\\-win64\\-[0-9]{6}.exe");
            Match matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
                return null;
            string newHash64Bit = matchHash.Value[..64];
            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = currentVersion;
            // e.g. https://github.com/mltframework/shotcut/releases/download/v21.05.18/shotcut-win64-210518.exe
            newInfo.install64Bit.downloadUrl = "https://github.com/mltframework/shotcut/releases/download/v" + currentVersion + "/shotcut-win64-" + currentVersion.Replace(".", "") + ".exe";
            newInfo.install64Bit.checksum = newHash64Bit;
            // Use same information for 32-bit build.
            newInfo.install32Bit = newInfo.install64Bit;
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
            return ["shotcut"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            var processes = new List<Process>();
            if (!string.IsNullOrWhiteSpace(detected.installPath))
            {
                // Uninstall previous version to avoid having two Shotcut entries in control panel.
                var proc = new Process();
                var path = Path.Combine(detected.installPath, "unins000.exe");
                if (File.Exists(path))
                {
                    // Inno Setup uninstaller
                    proc.StartInfo.FileName = path;
                    proc.StartInfo.Arguments = "/VERYSILENT /NORESTART";
                }
                else
                {
                    // older uninstaller
                    proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall.exe");
                    proc.StartInfo.Arguments = "/S";
                }
                processes.Add(proc);
                return processes;
            }

            var views = new List<RegistryView>(2) { RegistryView.Registry32 };
            if (Environment.Is64BitOperatingSystem)
            {
                views.Add(RegistryView.Registry64);
            }
            foreach (var view in views)
            {
                RegistryKey baseKey;
                try
                {
                    baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                }
                catch (PlatformNotSupportedException)
                {
                    // Should only happen on non-Windows platforms, but there we
                    // should not get to this point in the first place.
                    // But better be safe than sorry here.
                    logger.Warn("Error: This platform does not support or have a Windows Registry, so no information can be retrieved from it.");
                    continue;
                }
                try
                {
                    const string keyName = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Shotcut";
                    RegistryKey rKey = baseKey.OpenSubKey(keyName);
                    if (null == rKey)
                    {
                        continue;
                    }
                    try
                    {
                        object obj = rKey.GetValue("UninstallString");
                        if (null == obj)
                            continue;
                        string path = obj.ToString().Trim();
                        // Remove enclosing quotes.
                        if (path.StartsWith('\"') && path.EndsWith('\"'))
                        {
                            path = path[1..^1];
                        }
                        if (File.Exists(path))
                        {
                            var proc = new Process();
                            proc.StartInfo.FileName = path;
                            proc.StartInfo.Arguments = "/S";
                            processes.Add(proc);
                        }
                    }
                    finally
                    {
                        rKey.Close();
                    }
                }
                finally
                {
                    baseKey.Close();
                }
            } // foreach

            return processes;
        }


        /// <summary>
        /// Determines whether the pre-update processes are allowed to fail.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <param name="preProc">the current pre-update process</param>
        /// <returns>Returns true, if the separate processes returned by
        /// preUpdateProcess() are allowed to fail.</returns>
        public override bool allowPreUpdateProcessFailure(DetectedSoftware detected, Process preProc)
        {
            return true;
        }
    } // class
} // namespace
