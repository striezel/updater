/*
    This file is part of the updater command line interface.
    Copyright (C) 2024  Dirk Stolle

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
    /// Scribus Desktop Publishing software
    /// </summary>
    public class Scribus : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Scribus class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Scribus).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Scribus(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Scribus",
                "1.6.2",
                "^Scribus [0-9]+\\.[0-9]+\\.[0-9]+$",
                "^Scribus [0-9]+\\.[0-9]+\\.[0-9]+ \\(64bit\\)$",
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/scribus/scribus/1.6.2/scribus-1.6.2-windows.exe",
                    HashAlgorithm.SHA256,
                    "57065cfac522f6fa3d08de070df8a0bf84baa8eec881f4098a31c2a08a9690d6",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://netcologne.dl.sourceforge.net/project/scribus/scribus/1.6.2/scribus-1.6.2-windows-x64.exe",
                    HashAlgorithm.SHA256,
                    "6d83526a6ff88208e52c474ecbc8b714ee51d8e5e1672cd6527b98d9c4977706",
                    Signature.None,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["scribus"];
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
            logger.Info("Searching for newer version of Scribus. This may take a while, because the Scribus website can be slow to respond...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.scribus.net/downloads/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Scribus: " + ex.Message);
                return null;
            }

            // find version number
            var reVersion = new Regex("The current stable version of Scribus is ([0-9]+\\.[0-9]+\\.[0-9]+)\\.");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
            {
                return null;
            }
            var version = matchVersion.Groups[1].ValueSpan;
            // Cut things short, if the newest version is the known version.
            // That way we can avoid another slow HTTP(S) request.
            if (version == knownInfo().newestVersion)
            {
                return knownInfo();
            }

            // Find hashes: Those are available on the wiki on https://wiki.scribus.net/canvas/X.Y.Z_Release.
            try
            {
                string url = string.Concat("https://wiki.scribus.net/canvas/", version, "_Release");
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Scribus: " + ex.Message);
                return null;
            }
            /* Hashes are inside a table, e.g.:
               <tr>
               <td>Windows 32/64 Bit</td>
               <td>scribus-1.6.2-windows.exe</td>
               <td>57065cfac522f6fa3d08de070df8a0bf84baa8eec881f4098a31c2a08a9690d6</td>
               <td>83d8f205adba2b4a9e7ce71e94c007cdfed60faf
               </td></tr>
               <tr>
               <td>Windows 64 Bit</td>
               <td>scribus-1.6.2-windows-x64.exe</td>
               <td>6d83526a6ff88208e52c474ecbc8b714ee51d8e5e1672cd6527b98d9c4977706</td>
               <td>5c63c59f3c0b333fa1bcfd636a644c5a51701289
               </td></tr>
            */
            var reHash = new Regex("<td>scribus\\-" + Regex.Escape(version.ToString()) + "\\-windows.exe</td>\r?\n<td>([0-9a-f]{64})</td>");
            var matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
            {
                return null;
            }
            var newInfo = knownInfo();
            newInfo.install32Bit.checksum = matchHash.Groups[1].Value;

            reHash = new Regex("<td>scribus\\-" + Regex.Escape(version.ToString()) + "\\-windows\\-x64.exe</td>\r?\n<td>([0-9a-f]{64})</td>");
            matchHash = reHash.Match(htmlCode);
            if (!matchHash.Success)
            {
                return null;
            }
            newInfo.install64Bit.checksum = matchHash.Groups[1].Value;

            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(newInfo.newestVersion, version.ToString());
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(newInfo.newestVersion, version.ToString());
            newInfo.newestVersion = version.ToString();
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
                "Scribus"
            };
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
            if (string.IsNullOrWhiteSpace(detected.installPath) && string.IsNullOrWhiteSpace(detected.uninstallString))
                return null;
            string path = !string.IsNullOrWhiteSpace(detected.installPath) ? detected.installPath : Path.GetDirectoryName(detected.uninstallString);
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Scribus entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(path, "uninst.exe");
            proc.StartInfo.Arguments = "/S";
            processes.Add(proc);
            return processes;
        }
    } // class
} // namespace
