/*
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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Git for Windows.
    /// </summary>
    public class Git : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Git class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Git).FullName);


        /// <summary>
        /// publisher name for signed installers of Git for Windows
        /// </summary>
        private const string publisherX509 = "CN=Johannes Schindelin, O=Johannes Schindelin, S=Nordrhein-Westfalen, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2026, 5, 5, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public Git(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Git does not provide 32-bit binaries from version 2.49.0 onwards.");
                logger.Warn("Please consider switching to an 64-bit operating system to get newer Git updates.");
                return Last32BitVersion();
            }
            var signature = new Signature(publisherX509, certificateExpiration);
            var installer = new InstallInfoExe(
                "https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.exe",
                HashAlgorithm.SHA256,
                "726056328967f242fe6e9afbfe7823903a928aff577dcf6f517f2fb6da6ce83c",
                signature,
                "/VERYSILENT /NORESTART");
            return new AvailableSoftware("Git",
                "2.49.0",
                "^(Git|Git version [0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)$",
                "^(Git|Git version [0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)$",
                installer,
                installer);
        }


        /// <summary>
        /// Gets information about the latest version of Git that still has
        /// 32-bit builds.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public static AvailableSoftware Last32BitVersion()
        {
            var signature = new Signature(
                "CN=Johannes Schindelin, O=Johannes Schindelin, S=Nordrhein-Westfalen, C=DE",
                new(2026, 5, 5, 23, 59, 59, DateTimeKind.Utc));
            return new AvailableSoftware("Git",
                "2.48.1",
                "^(Git|Git version [0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)$",
                "^(Git|Git version [0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?)$",
                new InstallInfoExe(
                    "https://github.com/git-for-windows/git/releases/download/v2.48.1.windows.1/Git-2.48.1-32-bit.exe",
                    HashAlgorithm.SHA256,
                    "fdf9be6795afd911b4ed87417f2d5ac547798b5b47441b9f71984cddef943c3a",
                    signature,
                    "/VERYSILENT /NORESTART"),
                new InstallInfoExe(
                    "https://github.com/git-for-windows/git/releases/download/v2.48.1.windows.1/Git-2.48.1-64-bit.exe",
                    HashAlgorithm.SHA256,
                    "ce45e23275049f4b36edd90d5fd986a1e230efb6c511e9260a90176ce8e825df",
                    signature,
                    "/VERYSILENT /NORESTART"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["git", "git-for-windows"];
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
            logger.Info("Searching for newer version of Git for Windows...");
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("Git does not provide 32-bit binaries from version 2.49.0 onwards. Please consider switching to an 64-bit operating system to get newer Git updates.");
                return Last32BitVersion();
            }
            // Just getting the latest release does not work here, because that may also be a release candidate, and we do not want that.
            string html;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://github.com/git-for-windows/git/releases");
                task.Wait();
                html = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Git for Windows: " + ex.Message);
                return null;
            }

            // HTML text will contain links to releases like "https://github.com/git-for-windows/git/releases/tag/v2.30.1.windows.1".
            var reVersion = new Regex("git/releases/tag/v([0-9]+\\.[0-9]+\\.[0-9])\\.windows\\.([0-9]+)\"");
            int start = 0;
            do
            {
                var matchVersion = reVersion.Match(html, start);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Groups[1].Value;
                string fourthDigit = matchVersion.Groups[2].Value;
                string tag = matchVersion.Value.Remove(0, "git/releases/tag/".Length).Replace("\"", "");

                // Get checksum from release page, e.g. "https://github.com/git-for-windows/git/releases/tag/v2.30.1.windows.1"
                string htmlCode;
                try
                {
                    var task = client.GetStringAsync("https://github.com/git-for-windows/git/releases/tag/" + tag);
                    task.Wait();
                    htmlCode = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Git for Windows: " + ex.Message);
                    return null;
                }

                // find SHA256 hash for 64-bit installer
                /* Hash is part of a HTML table, e.g. in
                 * <td>Git-2.49.0-64-bit.exe</td>
                 * <td>726056328967f242fe6e9afbfe7823903a928aff577dcf6f517f2fb6da6ce83c</td>
                 */
                string escapedVersion = Regex.Escape(currentVersion);
                bool needsFourthDigit = fourthDigit != "1";
                Regex reHash = needsFourthDigit ?
                    new Regex("<td>Git\\-" + escapedVersion + "\\." + fourthDigit + "\\-64\\-bit\\.exe</td>\r?\n<td>([a-f0-9]{64})</td>")
                    : new Regex("<td>Git\\-" + escapedVersion + "\\-64\\-bit\\.exe</td>\r?\n<td>([a-f0-9]{64})</td>");
                Match matchHash = reHash.Match(htmlCode);
                if (!matchHash.Success)
                {
                    start = matchVersion.Index + 1;
                    continue;
                }
                string newHash = matchHash.Groups[1].Value;
                // construct new information
                var newInfo = knownInfo();
                if (needsFourthDigit)
                {
                    newInfo.newestVersion = currentVersion + "." + fourthDigit;
                    // e.g. https://github.com/git-for-windows/git/releases/download/v2.32.0.windows.2/Git-2.32.0.2-64-bit.exe
                    newInfo.install64Bit.downloadUrl = "https://github.com/git-for-windows/git/releases/download/" + tag + "/Git-" + currentVersion + "." + fourthDigit + "-64-bit.exe";
                }
                else
                {
                    newInfo.newestVersion = currentVersion;
                    // e.g. https://github.com/git-for-windows/git/releases/download/v2.30.0.windows.1/Git-2.30.0-64-bit.exe
                    newInfo.install64Bit.downloadUrl = "https://github.com/git-for-windows/git/releases/download/" + tag + "/Git-" + currentVersion + "-64-bit.exe";
                }
                newInfo.install64Bit.checksum = newHash;
                newInfo.install32Bit = newInfo.install64Bit;
                return newInfo;
            } while (true);
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return
            [
                "git", // Git itself
                "bash", // Git Bash
                "git-bash" // also Git Bash
            ];
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
            // When updating from a 32-bit installation to a 64-bit installation,
            // the old version has to be uninstalled first.
            return detected.appType == ApplicationType.Bit32 && Environment.Is64BitOperatingSystem;
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This may return an empty list, if no processes need to be run
        /// before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (detected.appType == ApplicationType.Bit64 || !Environment.Is64BitOperatingSystem)
            {
                return null;
            }

            string uninstallerPath = detected.uninstallString;
            if (string.IsNullOrEmpty(uninstallerPath))
            {
                // UninstallString is not set. Try to construct it from InstallLocation instead.
                if (string.IsNullOrEmpty(detected.installPath))
                {
                    throw new ArgumentNullException("detected.uninstallString", "Neither UninstallString nor InstallLocation are set for Git in the registry.");
                }
                if (detected.installPath.StartsWith('\"') && detected.installPath.EndsWith('\"'))
                {
                    uninstallerPath = Path.Combine(detected.installPath[1..^1], "uninst", "unins000.exe");
                    if (!File.Exists(uninstallerPath))
                    {
                        uninstallerPath = Path.Combine(detected.installPath[1..^1], "uninst", "unins001.exe");
                    }
                }
                else
                {
                    uninstallerPath = Path.Combine(detected.installPath, "uninst", "unins000.exe");
                    if (!File.Exists(uninstallerPath))
                    {
                        uninstallerPath = Path.Combine(detected.installPath, "uninst", "unins001.exe");
                    }
                }
            }

            // Remove enclosing quotes, if any.
            if (uninstallerPath.StartsWith('\"') && uninstallerPath.EndsWith('\"'))
            {
                uninstallerPath = uninstallerPath[1..^1];
            }

            var processes = new List<Process>(1);
            var proc = new Process();
            proc.StartInfo.FileName = uninstallerPath;
            proc.StartInfo.Arguments = "/VERYSILENT /NORESTART";
            processes.Add(proc);
            return processes;
        }
    } // class
} // namespace
