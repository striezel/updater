/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021  Dirk Stolle

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
using System.Net;
using System.Text.RegularExpressions;
using System.Diagnostics;
using updater.data;
using System.Collections.Generic;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Inkscape.
    /// </summary>
    public class Inkscape : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Inkscape class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Inkscape).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Inkscape(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Inkscape",
                "1.1.1",
                "^Inkscape( [0-9]\\.[0-9]+(\\.[0-9]+)?)?$",
                "^Inkscape( [0-9]\\.[0-9]+(\\.[0-9]+)?)?$",
                new InstallInfoMsi(
                    "https://media.inkscape.org/dl/resources/file/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x86.msi",
                    HashAlgorithm.SHA256,
                    "a0cd0295cd94961684c3f29dd6185116e8fd04876b60d43220ad467e5bb173f3",
                    Signature.None,
                    "/qn /norestart"),
                new InstallInfoMsi(
                    "https://media.inkscape.org/dl/resources/file/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x64.msi",
                    HashAlgorithm.SHA256,
                    "60260f865f1a0ca9e538cf24a7999276281b130810c792dce131f73df4914cbc",
                    Signature.None,
                    "/qn /norestart")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "inkscape" };
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
            logger.Info("Searching for newer version of Inkscape...");
            string htmlCode = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlCode = client.DownloadString("https://inkscape.org/release/");
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Inkscape: " + ex.Message);
                    return null;
                }
                client.Dispose();
            }

            // Search for URL part like "/release/0.92.4/windows/".
            Regex reVersion = new Regex("/release/[0-9]\\.[0-9]+(\\.[0-9]+)?/windows/");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string newVersion = matchVersion.Value.Replace("/release/", "").Replace("/windows/", "").Trim();
            
            // construct new version information based on old information
            var newInfo = knownInfo();
            if (newVersion == newInfo.newestVersion)
                return newInfo;
            newInfo.newestVersion = newVersion;
            // Reset checksums to avoid working with older stuff.
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;

            foreach (string bits in new string[] {"32", "64" })
            {
                // Find download URL for 32 bit version.
                // https://inkscape.org/release/inkscape-0.92.4/windows/32-bit/msi/dl/
                // 64 bit version is at an URL like
                // https://inkscape.org/release/inkscape-0.92.4/windows/64-bit/msi/dl/
                htmlCode = null;
                using (var client = new WebClient())
                {
                    try
                    {
                        htmlCode = client.DownloadString("https://inkscape.org/release/inkscape-" + newVersion + "/windows/" + bits + "-bit/msi/dl/");
                    }
                    catch (Exception ex)
                    {
                        logger.Warn("Exception occurred while checking for newer version of Inkscape: " + ex.Message);
                        return null;
                    }
                    client.Dispose();
                }

                // Search for URL part like '<a href="/gallery/item/29346/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x86.msi">'.
                //     or
                // Search for URL part like '<a href="/gallery/item/29350/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x64.msi">'.
                string arch = (bits == "32") ? "x86" : "x64";
                string dateAndHash = null;
                {
                    Regex reUrl = new Regex("<a href=\"([a-zA-Z0-9\\/]+)/inkscape\\-" + Regex.Escape(newVersion) + "(_2[0-9]{3}\\-[0-9]{2}\\-[0-9]{2}_[0-9a-f]+)\\-" + arch + "\\.msi\">");
                    Match matchUrl = reUrl.Match(htmlCode);
                    if (!matchUrl.Success)
                        return null;
                    if (bits == "32")
                        newInfo.install32Bit.downloadUrl = "https://inkscape.org/" + matchUrl.Groups[1].Value + "inkscape-" + newVersion + matchUrl.Groups[2].Value + "-x86.msi";
                    else
                        newInfo.install64Bit.downloadUrl = "https://inkscape.org/" + matchUrl.Groups[1].Value + "inkscape-" + newVersion + matchUrl.Groups[2].Value + "-x64.msi";
                    dateAndHash = matchUrl.Groups[2].Value;
                }

                // Signature files are given in HTML elements like
                // <a href="https://media.inkscape.org/media/resources/sigs/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x86.msi.sha256"> or
                // <a href="https://media.inkscape.org/media/resources/sigs/inkscape-1.1.1_2021-09-20_3bf5ae0d25-x64.msi.sha256">.
                {
                    string signatureUrl = "https://media.inkscape.org/media/resources/sigs/inkscape-" + newVersion + dateAndHash + "-" + arch + ".msi.sha256";

                    htmlCode = null;
                    using (var client = new WebClient())
                    {
                        try
                        {
                            htmlCode = client.DownloadString(signatureUrl);
                        }
                        catch (Exception ex)
                        {
                            logger.Warn("Exception occurred while checking for newer version of Inkscape: " + ex.Message);
                            return null;
                        }
                        client.Dispose();
                    }
                }

                Regex reHash = new Regex("[0-9a-f]{64} [ \\*]inkscape\\-" + Regex.Escape(newVersion + dateAndHash) + "\\-" + arch + "\\.msi");
                Match matchHash = reHash.Match(htmlCode);
                if (!matchHash.Success)
                    return null;
                string newHash = matchHash.Value.Substring(0, 64); // SHA256 is 64 characters in hex.
                if (bits == "32")
                {
                    newInfo.install32Bit.checksum = newHash;
                    newInfo.install32Bit.algorithm = HashAlgorithm.SHA256;
                }
                else
                {
                    newInfo.install64Bit.checksum = newHash;
                    newInfo.install64Bit.algorithm = HashAlgorithm.SHA256;
                }
            } // foreach

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
            return new List<string>();
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
            // The pre-update processes basically need to uninstall all older
            // versions before installing the newest version.
            // It is a requirement for the older .exe installer-based versions,
            // because they are incompatible with MSI. On the other hand the
            // MSI installers do not allow to install/update, if another MSI
            // version is already installed.
            if (string.IsNullOrWhiteSpace(detected.displayVersion))
                return null;

            var processes = new List<Process>();
            //Versions before 0.91 (i.e. exe-installers) can be uninstalled via
            // "%PROGRAMFILES%\Inkscape\uninstall.exe" /S
            string path;
            if (!string.IsNullOrWhiteSpace(detected.installPath))
                path = Path.Combine(detected.installPath, "uninstall.exe");
            else
                path = "C:\\Program Files (x86)\\Inkscape\\uninstall.exe";
            if (File.Exists(path))
            {
                var proc = new Process();
                proc.StartInfo.FileName = path;
                proc.StartInfo.Arguments = "/S";
                processes.Add(proc);
            }
            else if (File.Exists("C:\\Program Files\\Inkscape\\uninstall.exe"))
            {
                var proc = new Process();
                proc.StartInfo.FileName = "C:\\Program Files\\Inkscape\\uninstall.exe";
                proc.StartInfo.Arguments = "/S";
                processes.Add(proc);
            }
            else
            {
                // MSI GUIDs to uninstall older MSI builds
                string[] guids = {
                    "{81922150-317E-4BB0-A31D-FF1C14F707C5}", // 0.91 MSI (x86 and x64), 0.92 MSI
                    "{1E74336F-9E7A-4070-BAA7-716A504FB9B0}", // 1.0 MSI
                    "{776C087E-B714-4153-9414-79592EC61B4A}", // 1.0.1 MSI
                    "{DBDA3649-0685-4067-ADB6-7A3B9B30720F}", // 1.0.2-2 MSI
                    "{BB039842-4166-4A3C-90BC-316F6E6BDC83}", // 1.1.0 MSI
                    "{2B0B7E83-63A3-4B06-B501-F01ED3A14D64}", // 1.1.1 MSI
                };
                foreach (var id in guids)
                {
                    var proc = new Process();
                    proc.StartInfo.FileName = "msiexec.exe";
                    proc.StartInfo.Arguments = "/qn /x" + id;
                    processes.Add(proc);
                } // foreach
            } // else
            return processes;
        }


        /// <summary>
        /// Determines whether or not the pre-update processes are allowed to fail.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <param name="preProc">the current pre-update process</param>
        /// <returns>Returns true, if the separate processes returned by
        /// preUpdateProcess() are allowed to fail.</returns>
        public override bool allowPreUpdateProcessFailure(DetectedSoftware detected, Process preProc)
        {
            // Preparational processes are allowed to fail, because usually not
            // all of the older MSI installations are present, but we need to
            // try to uninstall them before installing the current version.
            return preProc.StartInfo.FileName.ToLower().Contains("msiexec.exe");
        }


        /// <summary>
        /// whether the detected software is older than the newest known software
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            Regex re = new Regex("[0-9]\\.[0-9]+(\\.[0-9]+)?");
            Match m = re.Match(detected.displayName);
            if (m.Success)
            {
                // Use version number from name, because it is more accurate.
                return (string.Compare(m.Value, info().newestVersion, true) < 0);
            }
            else
            {
                // Fall back to displayed version. However, this is inaccurate,
                // because versions like 0.92.1 will only show up as 0.92, thus
                // always triggering an update.
                return (string.Compare(detected.displayVersion, info().newestVersion, true) < 0);
            }
        }

    } // class
} // namespace
