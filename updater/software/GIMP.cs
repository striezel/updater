/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates for the GNU Image Manipulation Program (GIMP).
    /// </summary>
    public class GIMP : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for GIMP class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(GIMP).FullName);


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Jernej Simončič, O=Jernej Simončič, L=Ljubljana, C=SI";


        /// <summary>
        /// expiration date of the certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 2, 28, 6, 22, 14, DateTimeKind.Utc);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public GIMP(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var installer = new InstallInfoExe(
                "https://download.gimp.org/pub/gimp/v3.0/windows/gimp-3.0.0-setup.exe",
                HashAlgorithm.SHA256,
                "ab6f9aa481120097f032c39f07cb70990929878fa65bf4ec6d1669d7a616770a",
                new Signature(publisherX509, certificateExpiration),
                "/VERYSILENT /NORESTART /ALLUSERS");

            return new AvailableSoftware("The GIMP",
                "3.0.0",
                "^GIMP [0-9]+\\.[0-9]+\\.[0-9]+(\\-[0-9]+)?$",
                "^GIMP [0-9]+\\.[0-9]+\\.[0-9]+(\\-[0-9]+)?$",
                // The GIMP uses the same installer for 32 and 64-bit.
                installer,
                installer);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["gimp"];
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
            logger.Info("Searching for newer version of GIMP...");
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://www.gimp.org/downloads/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Error("Exception occurred while checking for newer version of GIMP: " + ex.Message);
                return null;
            }

            const string stableRelease = "The current stable release of GIMP is";
            int idx = htmlCode.IndexOf(stableRelease);
            if (idx < 0)
                return null;
            htmlCode = htmlCode[idx..];

            var reVersion = new Regex("[0-9]+\\.[0-9]+\\.[0-9]+");
            Match matchVersion = reVersion.Match(htmlCode);
            if (!matchVersion.Success)
                return null;
            string version = matchVersion.Value;

            // SHA-256 checksum is in a file like
            // https://download.gimp.org/pub/gimp/v2.8/windows/gimp-2.8.20-setup.exe.sha256
            string shortVersion = string.Join(".", version.Split(['.']), 0, 2);
            htmlCode = null;
            using (var h_client = new HttpClient())
            {
                try
                {
                    string sha256Url = "https://download.gimp.org/pub/gimp/v" + shortVersion + "/windows/gimp-" + version + "-setup.exe.sha256";
                    var task = h_client.GetStringAsync(sha256Url);
                    task.Wait();
                    htmlCode = task.Result;
                }
                catch (Exception ex)
                {
                    if ((ex.InnerException is HttpRequestException)
                        && ((ex.InnerException as HttpRequestException).StatusCode == HttpStatusCode.NotFound))
                    {
                        // try SHA256 file for whole directory instead
                        try
                        {
                            string sha256Url = "https://download.gimp.org/pub/gimp/v" + shortVersion + "/windows/SHA256SUMS";
                            var task = h_client.GetStringAsync(sha256Url);
                            task.Wait();
                            htmlCode = task.Result;
                        }
                        catch (Exception ex2)
                        {
                            logger.Warn("Exception occurred while checking for newer version of GIMP: " + ex2.Message);
                            return null;
                        } // try-catch (inner)
                    } // if 404 Not Found

                    // Other exceptions are still errors.
                    else
                    {
                        logger.Warn("Exception occurred while checking for newer version of GIMP: " + ex.Message);
                        return null;
                    }
                }
                h_client.Dispose();
            } // using

            var reChecksum = new Regex("[0-9a-f]{64}  gimp\\-" + Regex.Escape(version) + "\\-setup(\\-[0-9]+)?\\.exe");
            var matches = reChecksum.Matches(htmlCode);
            if (matches.Count == 0)
                return null;
            string checksum = null;
            int revision = -1;
            foreach (Match match in matches)
            {
                int current_revision = -1;
                if (match.Groups[1].Success)
                {
                    if (!int.TryParse(match.Groups[1].Value.AsSpan(1), out current_revision))
                    {
                        return null;
                    }
                }
                else
                {
                    current_revision = 0;
                }
                if (current_revision > revision)
                {
                    checksum = match.Value[..64];
                    revision = current_revision;
                }
            }

            // construct new information
            var newInfo = knownInfo();
            newInfo.newestVersion = revision <= 0 ? version : version + "." + revision.ToString();
            // 32-bit
            newInfo.install32Bit.downloadUrl = revision <= 0 ?
                "https://download.gimp.org/pub/gimp/v" + shortVersion + "/windows/gimp-" + version + "-setup.exe"
                : "https://download.gimp.org/pub/gimp/v" + shortVersion + "/windows/gimp-" + version + "-setup-" + revision.ToString() + ".exe";
            newInfo.install32Bit.checksum = checksum;
            // 64-bit - same installer, same checksum
            newInfo.install64Bit.downloadUrl = newInfo.install32Bit.downloadUrl;
            newInfo.install64Bit.checksum = checksum;
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
            return [];
        }


        /// <summary>
        /// Checks whether a detected version is version 2.x or older.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if the detected version is version 2.x or
        /// older. Returns false otherwise.
        /// Also returns false, if the version is not set.</returns>
        private static bool isVersion2OrLess(DetectedSoftware detected)
        {
            return !string.IsNullOrEmpty(detected.displayVersion)
                && new Quartet(detected.displayVersion).major <= 2;
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
            // When updating from GIMP 2.x (or older), the old version has to
            // be uninstalled first. Otherwise we end up with two installed
            // versions of GIMP.
            return isVersion2OrLess(detected);
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
            if (!isVersion2OrLess(detected))
            {
                return null;
            }

            string uninstallerPath = detected.uninstallString;
            if (string.IsNullOrEmpty(uninstallerPath))
            {
                // UninstallString is not set. Try to construct it from InstallLocation instead.
                if (string.IsNullOrEmpty(detected.installPath))
                {
                    throw new ArgumentNullException("detected.uninstallString", "Neither UninstallString nor InstallLocation are set for GIMP in the registry.");
                }
                if (detected.installPath.StartsWith('\"') && detected.installPath.EndsWith('\"'))
                {
                    uninstallerPath = Path.Combine(detected.installPath[1..^1], "uninst", "unins000.exe");
                }
                else
                {
                    uninstallerPath = Path.Combine(detected.installPath, "uninst", "unins000.exe");
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


        /// <summary>
        /// Checks whether the software is in the list of detected software.
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public override void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            // Note: This is basically the default implementation of
            // detectionQuery() from the AbstractSoftware class, but with a
            // minor change to get the correct version including the possibly
            // present revision number to ensure the revision number is
            // detected, too.
            var known = knownInfo();
            if (Environment.Is64BitOperatingSystem && !string.IsNullOrWhiteSpace(known.match64Bit))
            {
                var regularExp = new Regex(known.match64Bit, RegexOptions.IgnoreCase);
                int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                if ((idx >= 0) && (detected[idx].appType == ApplicationType.Bit64))
                {
                    // found it
                    autoGetNewer(autoGetNew);
                    DetectedSoftware detected_fixed = new(detected[idx].displayName, detected[idx].displayVersion, detected[idx].installPath, detected[idx].uninstallString, detected[idx].appType);
                    var re = new Regex("^GIMP ([0-9]+\\.[0-9]+\\.[0-9]+(\\-[0-9]+)?)$");
                    var match = re.Match(detected_fixed.displayName);
                    if (match.Success)
                    {
                        string real_version = match.Groups[1].Value.Replace('-', '.');
                        detected_fixed.displayVersion = real_version;
                    }
                    bool updatable = needsUpdate(detected_fixed);
                    result.Add(new QueryEntry(this, detected_fixed, updatable, ApplicationType.Bit64));
                } // if match was found
            } // if 64-bit expression does exist and we are on a 64-bit system
            if (!string.IsNullOrWhiteSpace(known.match32Bit))
            {
                var regularExp = new Regex(known.match32Bit, RegexOptions.IgnoreCase);
                int idx = detected.FindIndex(x => regularExp.IsMatch(x.displayName) && !string.IsNullOrWhiteSpace(x.displayVersion));
                if ((idx >= 0) && (detected[idx].appType == ApplicationType.Bit32))
                {
                    // found it
                    autoGetNewer(autoGetNew);
                    DetectedSoftware detected_fixed = new(detected[idx].displayName, detected[idx].displayVersion, detected[idx].installPath, detected[idx].uninstallString, detected[idx].appType);
                    var re = new Regex("^GIMP ([0-9]+\\.[0-9]+\\.[0-9]+(\\-[0-9]+)?)$");
                    var match = re.Match(detected_fixed.displayName);
                    if (match.Success)
                    {
                        string real_version = match.Groups[1].Value.Replace('-', '.');
                        detected_fixed.displayVersion = real_version;
                    }
                    bool updatable = needsUpdate(detected_fixed);
                    result.Add(new QueryEntry(this, detected_fixed, updatable, ApplicationType.Bit32));
                } // if match was found
            } // if 32-bit expression does exist
        }
    } // class
} // namespace
